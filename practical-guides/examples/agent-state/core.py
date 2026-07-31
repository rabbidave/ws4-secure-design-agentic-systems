"""
agent_state.core
================

Engine-agnostic definition of "agent-state": a per-forward-pass inventory
of what a model had available to it at the moment it produced a step of
output, plus a hash chain over those inventories.

This is deliberately NOT an "activity" record (it doesn't say what the
model did, or what was permitted/denied). It's an INVENTORY record: a
point-in-time snapshot of the model's addressable surface -- tool
schemas, active adapters, sampling config, batch composition -- taken
once per forward pass. That's the OCSF-shape distinction from the
Router/API-Activity gap analysis: this belongs in a Discovery-category
"Inventory Info" class (alongside Device Inventory Info / User Inventory
Info), not in API Activity.

No third-party dependencies. This module is fully runnable/testable on
its own -- see demo.py -- independent of whether vllm or llama-cpp-python
are installed.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

SCHEMA_VERSION = "agent-state/1.0"

GENESIS_HASH = "0" * 64  # chain root sentinel


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """
    Deterministic serialization: sorted keys, no whitespace ambiguity,
    fixed float formatting via json's default repr. Two logically-identical
    payloads always produce identical bytes, which is the whole point of
    hashing them.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _sha256_hex(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


@dataclass(frozen=True)
class ToolInventory:
    """What the model could call at this forward pass."""
    tool_names: tuple[str, ...] = ()
    tool_schema_hash: Optional[str] = None  # sha256 over canonical tool schemas

    @staticmethod
    def from_schemas(schemas: list[dict[str, Any]]) -> "ToolInventory":
        if not schemas:
            return ToolInventory()
        names = tuple(sorted(s.get("name") or s.get("function", {}).get("name", "?") for s in schemas))
        digest = _sha256_hex(_canonical_bytes({"tools": schemas}))
        return ToolInventory(tool_names=names, tool_schema_hash=digest)


@dataclass(frozen=True)
class ContextInventory:
    """What context/config shaped this forward pass."""
    prompt_token_count: Optional[int] = None
    context_hash: Optional[str] = None  # hash of the actual token ids in context
    sampling_params_hash: Optional[str] = None
    lora_adapters: tuple[str, ...] = ()
    kv_state_hash: Optional[str] = None  # hash of the engine's actual post-decode KV-cache state

    @staticmethod
    def build(
        token_ids: Optional[list[int]] = None,
        sampling_params: Optional[dict[str, Any]] = None,
        lora_adapters: Optional[list[str]] = None,
        kv_state_material: Optional[bytes] = None,
    ) -> "ContextInventory":
        """
        `kv_state_material` is already-serialized bytes, not a structure to
        canonicalize -- the two engines produce fundamentally different kinds
        of material here (llama.cpp: raw session-state bytes from the C API;
        vLLM: canonical JSON bytes over the paged-attention block table, since
        the raw KV tensors aren't cleanly exposed at the LLMEngine surface).
        Each hook is responsible for producing deterministic bytes for its
        own engine; this is the one place they all get hashed the same way,
        so there's still exactly one digest function in the package.
        """
        context_hash = _sha256_hex(_canonical_bytes({"tokens": token_ids})) if token_ids else None
        sampling_hash = _sha256_hex(_canonical_bytes(sampling_params)) if sampling_params else None
        kv_hash = _sha256_hex(kv_state_material) if kv_state_material else None
        return ContextInventory(
            prompt_token_count=len(token_ids) if token_ids else None,
            context_hash=context_hash,
            sampling_params_hash=sampling_hash,
            lora_adapters=tuple(sorted(lora_adapters or [])),
            kv_state_hash=kv_hash,
        )


@dataclass(frozen=True)
class EngineIdentity:
    name: str          # "vllm" | "llama.cpp"
    version: str
    model_name: str
    model_revision: Optional[str] = None   # weights hash/commit if available
    dtype: Optional[str] = None
    quantization: Optional[str] = None


@dataclass(frozen=True)
class AgentStateInventory:
    """
    One per-forward-pass inventory record. `inventory_hash` and
    `prior_inventory_hash` are populated by AgentStateChain, not by
    the caller -- the record is meaningless as a security artifact
    until it's been chained.
    """
    schema_version: str
    forward_pass_seq: int
    captured_at_ns: int
    engine: EngineIdentity
    session_uid: str
    batch_sequence_uids: tuple[str, ...]
    tools: ToolInventory
    context: ContextInventory
    prior_inventory_hash: Optional[str] = None
    inventory_hash: Optional[str] = None

    def payload_for_hash(self) -> dict[str, Any]:
        """Everything except inventory_hash itself feeds the hash."""
        d = asdict(self)
        d.pop("inventory_hash", None)
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentStateChain:
    """
    Per-process (or per-session) hash chain over successive forward passes.
    Because each hash covers (prior_hash + this payload), a change to any
    earlier record invalidates every hash after it -- the same tamper-
    evidence property as a transparency log, without needing an external
    log service to get useful integrity guarantees within a session.
    """

    def __init__(self, session_uid: str):
        self.session_uid = session_uid
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self.records: list[AgentStateInventory] = []
        self._on_record: list[Callable[[AgentStateInventory], None]] = []
        self._on_verify_failure: list[Callable[[int, AgentStateInventory, str], None]] = []

    def on_record(self, callback: Callable[[AgentStateInventory], None]) -> None:
        """Subscribe to newly-chained inventory records."""
        self._on_record.append(callback)

    def on_verify_failure(self, callback: Callable[[int, AgentStateInventory, str], None]) -> None:
        """Subscribe to per-record verify failures (idx, record, reason)."""
        self._on_verify_failure.append(callback)

    def record(
        self,
        engine: EngineIdentity,
        batch_sequence_uids: list[str],
        tools: ToolInventory,
        context: ContextInventory,
    ) -> AgentStateInventory:
        seq = self._seq
        self._seq += 1

        draft = AgentStateInventory(
            schema_version=SCHEMA_VERSION,
            forward_pass_seq=seq,
            captured_at_ns=time.time_ns(),
            engine=engine,
            session_uid=self.session_uid,
            batch_sequence_uids=tuple(sorted(batch_sequence_uids)),
            tools=tools,
            context=context,
            prior_inventory_hash=self._last_hash,
        )
        digest = _sha256_hex(
            self._last_hash.encode("ascii"),
            _canonical_bytes(draft.payload_for_hash()),
        )
        finalized = _with_hash(draft, digest)

        self._last_hash = digest
        self.records.append(finalized)
        for cb in list(self._on_record):
            cb(finalized)
        return finalized

    def verify(self) -> bool:
        """Recompute the chain from scratch; True iff nothing was tampered with."""
        expected_prior = GENESIS_HASH
        for idx, rec in enumerate(self.records):
            if rec.prior_inventory_hash != expected_prior:
                self._fire_verify_failure(idx, rec, "prior_inventory_hash mismatch")
                return False
            recomputed = _sha256_hex(
                expected_prior.encode("ascii"),
                _canonical_bytes(rec.payload_for_hash()),
            )
            if recomputed != rec.inventory_hash:
                self._fire_verify_failure(idx, rec, "inventory_hash mismatch")
                return False
            expected_prior = rec.inventory_hash
        return True

    def _fire_verify_failure(self, idx: int, rec: AgentStateInventory, reason: str) -> None:
        # Subscriber exceptions must not poison verify()'s boolean result.
        for cb in list(self._on_verify_failure):
            try:
                cb(idx, rec, reason)
            except Exception:
                pass


def _with_hash(draft: AgentStateInventory, digest: str) -> AgentStateInventory:
    # dataclasses are frozen; rebuild rather than mutate.
    kwargs = draft.to_dict()
    kwargs["engine"] = draft.engine
    kwargs["tools"] = draft.tools
    kwargs["context"] = draft.context
    kwargs["batch_sequence_uids"] = draft.batch_sequence_uids
    kwargs["inventory_hash"] = digest
    return AgentStateInventory(**kwargs)
