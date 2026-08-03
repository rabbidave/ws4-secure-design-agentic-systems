"""
agent_state.ocsf_mapping
========================

Converts a core.AgentStateInventory record into the proposed OCSF
class `Agent Inventory Info [5050]`, a new class under Category 5
(Discovery) -- syntactically a sibling of Device Inventory Info
[5001], User Inventory Info [5003], Software Inventory Info [5020],
Cloud Resources Inventory Info [5023], and Live Evidence Info [5040].

Structural rationale (kept short -- see SPEC.md for the full table):
  * activity_id = 0 (Unknown). This is *not* an Activity-category
    event. There is no actor, no action verb, no allow/deny decision,
    no HTTP/RPC request pair. Forcing it through API Activity [6003]
    would require manufacturing those fields with synthetic values.
  * The three inventory objects (tools / context / batch) parallel
    `groups` / `credentials` / `account` under User Inventory Info --
    they describe the addressable surface at the moment of capture,
    not what was done with it.

No third-party deps. Reads only from core.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from core import AgentStateInventory, SCHEMA_VERSION

# OCSF class identity constants.
CLASS_UID = 5050
CLASS_NAME = "Agent Inventory Info"
CATEGORY_UID = 5
CATEGORY_NAME = "Discovery"
ACTIVITY_ID = 0
ACTIVITY_NAME = "Unknown"
TYPE_UID = CLASS_UID * 100 + ACTIVITY_ID
TYPE_NAME = f"{CLASS_NAME}:{ACTIVITY_NAME}"

INSTRUMENTATION_NAME = "agent-state"
INSTRUMENTATION_VERSION = "1.0"

# OCSF Fingerprint object (observable_id 30).
# algorithm_id enum: 0=Unknown, 1=MD5, 2=SHA-1, 3=SHA-256, 4=SHA-512,
# 5=CTPH, 6=TLSH, 7=quickXorHash, 99=Other.
SHA256_ALGORITHM_ID = 3
SHA256_ALGORITHM_NAME = "SHA-256"


def _fingerprint(value: Optional[str]) -> Optional[dict[str, Any]]:
    """
    Build an OCSF Fingerprint object from a hex digest. Returns None when
    the underlying field is None (engine didn't capture that sub-hash),
    which the spec marks as omitted-optional -- the same shape the
    Fingerprint object is profiled to support.
    """
    if value is None:
        return None
    return {
        "algorithm_id": SHA256_ALGORITHM_ID,
        "algorithm": SHA256_ALGORITHM_NAME,
        "value": value,
    }


def _agent_object(rec: AgentStateInventory) -> dict[str, Any]:
    """
    OCSF's real `ai_agent` object (objects/ai_agent.json upstream), not a
    bespoke shape: `uid` is the stable identity issued by the agent's
    authoritative source, `instance_uid` scopes to this session,
    `version`/`charter` are the agent's own config revision and charter
    document (both distinct from the model backing it -- that's `engine`/
    `model` elsewhere on this event, OCSF's `ai_model` concept).

    `session_token` is deliberately never included here -- it already fed
    the hash chain via `payload_for_hash()` before this function ever runs,
    so tampering with it is still caught. Only its fingerprint is exposed,
    so a bearer credential never lands in an OCSF sink/SIEM.
    """
    return {
        "uid": rec.agent.uid,
        "instance_uid": rec.agent.instance_uid,
        "version": rec.agent.version,
        "charter": rec.agent.charter,
        "token_fingerprint": _fingerprint(rec.agent.token_fingerprint()),
    }


def _tools_object(rec: AgentStateInventory) -> dict[str, Any]:
    return {
        "names": list(rec.tools.tool_names),
        "schema_fingerprint": _fingerprint(rec.tools.tool_schema_hash),
    }


def _context_object(rec: AgentStateInventory) -> dict[str, Any]:
    return {
        "prompt_token_count": rec.context.prompt_token_count,
        "context_fingerprint": _fingerprint(rec.context.context_hash),
        "sampling_params_fingerprint": _fingerprint(rec.context.sampling_params_hash),
        "lora_adapters": list(rec.context.lora_adapters),
        "kv_state_fingerprint": _fingerprint(rec.context.kv_state_hash),
    }


def _batch_object(rec: AgentStateInventory) -> dict[str, Any]:
    return {
        "request_uids": list(rec.batch_sequence_uids),
    }


def _metadata_object() -> dict[str, Any]:
    return {
        "product": {
            "name": INSTRUMENTATION_NAME,
            "version": INSTRUMENTATION_VERSION,
        },
        "extension": {
            "name": "agent-state",
            "uid": "5050",
            "version": SCHEMA_VERSION,
        },
    }


def to_ocsf_event(rec: AgentStateInventory) -> dict[str, Any]:
    """
    Map one core.AgentStateInventory into the OCSF class shape proposed
    in SPEC.md §2. The mapping is total -- every field on the input
    record is reflected on the output event; nothing is dropped.

    The output is plain JSON-serializable; pass through the sink-shape
    canonicalizer of your OCSF collector (most sinks sort+compact on
    ingest, which is fine -- canonicalization matters for hashing, and
    hashing already happened on the canonical reference shape inside
    core.AgentStateChain before this function is called).
    """
    return {
        # Class identity
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "activity_id": ACTIVITY_ID,
        "activity_name": ACTIVITY_NAME,
        "type_uid": TYPE_UID,
        "type_name": TYPE_NAME,
        # Discovery-side identification
        "ai_agent": _agent_object(rec),
        "agent_type": "llm_forward_pass",
        "engine": rec.engine.name,
        "engine_version": rec.engine.version,
        "model": rec.engine.model_name,
        "model_revision": rec.engine.model_revision,
        "instrumentation_library_name": INSTRUMENTATION_NAME,
        "instrumentation_library_version": INSTRUMENTATION_VERSION,
        # Session / chain topology (Fingerprint objects, not bare hash_t)
        "session_uid": rec.agent.instance_uid,
        "forward_pass_seq": rec.forward_pass_seq,
        "captured_at": rec.captured_at_ns // 1_000_000_000,
        "prev_inventory": _fingerprint(rec.prior_inventory_hash),
        "inventory": _fingerprint(rec.inventory_hash),
        # Surface inventory
        "tools": _tools_object(rec),
        "context": _context_object(rec),
        "batch": _batch_object(rec),
        # Provenance metadata
        "metadata": _metadata_object(),
    }


def canonical_ocsf_bytes(rec: AgentStateInventory) -> bytes:
    """
    Bytes that should match if anyone independently reconstructs the
    OCSF event and re-hashes it. Reuses the exact canonicalization
    rules from core._canonical_bytes (sorted keys, no whitespace,
    strict ASCII), so a round-trip `to_ocsf_event` -> hash is
    deterministic across Python versions and transports.
    """
    return json.dumps(
        to_ocsf_event(rec),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
