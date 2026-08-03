"""
agent_state.demo
=================

Stdlib-only end-to-end demonstration of the agent-state inventory chain.
Does NOT import vllm_hook or llamacpp_hook (those need their respective
backends installed); it exercises the engine-agnostic core, the OCSF
mapping, and the OTel bridge using a FakeEngine that mimics the surface
both real hooks consume from their underlying engines.

Run:
    python Agent.State/demo.py

Exits 0 on success. Prints the OCSF rendering of one inventory record.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Optional

# Allow running as `python Agent.State/demo.py` from the parent dir
# as well as `python demo.py` from inside Agent.State/.
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    AgentIdentity,
    AgentStateChain,
    ContextInventory,
    EngineIdentity,
    ToolInventory,
)
from ocsf_mapping import to_ocsf_event, CLASS_UID, TYPE_UID
from otel_bridge import AgentStateOTelBridge, EVENT_NAME


# ---------------------------------------------------------------------------
# FakeEngine -- mimics what the real hooks consume from their backends
# ---------------------------------------------------------------------------

class FakeEngine:
    """
    Plays the role of (vllm.LLMEngine.scheduler.running) for the demo:
    each forward pass reveals a new (request_ids, token_ids, sampling_params,
    tools, loras) tuple, in the same shape AgentStateChain.record expects.
    """

    def __init__(self) -> None:
        # Three forward passes with varying tool sets, mimicking
        # tool binding / unbinding across a multi-turn conversation.
        self.passes: list[dict[str, Any]] = [
            {
                "request_ids": ["req-1"],
                "token_ids": list(range(1, 33)),
                "sampling_params": {"temperature": 0.7, "top_p": 0.9},
                "tools": [
                    {"name": "search", "parameters": {"q": "str"}},
                    {"name": "calculator", "parameters": {"expr": "str"}},
                ],
                "lora_adapters": ["base-lora"],
            },
            {
                "request_ids": ["req-1", "req-2"],  # batching two sequences
                "token_ids": list(range(1, 65)),
                "sampling_params": {"temperature": 0.7, "top_p": 0.9},
                "tools": [
                    {"name": "search", "parameters": {"q": "str"}},
                    {"name": "calculator", "parameters": {"expr": "str"}},
                    {"name": "summarize", "parameters": {"text": "str"}},
                ],
                "lora_adapters": ["base-lora"],
            },
            {
                "request_ids": ["req-2"],  # req-1 finished, tools unbound
                "token_ids": list(range(1, 17)),
                "sampling_params": {"temperature": 0.3, "top_p": 1.0},
                "tools": [
                    {"name": "summarize", "parameters": {"text": "str"}},
                ],
                "lora_adapters": [],
            },
        ]
        self._i = 0

    def __iter__(self) -> "FakeEngine":
        return self

    def __next__(self) -> dict[str, Any]:
        if self._i >= len(self.passes):
            raise StopIteration
        p = self.passes[self._i]
        self._i += 1
        return p


ENGINE_IDENTITY = EngineIdentity(
    name="fake-engine",
    version="0.0.0-demo",
    model_name="FakeModel-1.0",
    model_revision="sha256:demo-weights",
    dtype="fp16",
    quantization=None,
)


# ---------------------------------------------------------------------------
# Bridge that captures emitted OTel events for inspection
# ---------------------------------------------------------------------------

class CapturingSpan:
    """Mimics otel_bridge._SpanLike.add_event."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def add_event(self, name: str, attributes: Optional[dict[str, Any]] = None) -> None:
        self.events.append((name, dict(attributes or {})))


# ---------------------------------------------------------------------------
# Main scenario
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("agent-state demo -- 3 forward passes, tamper-evidence check")
    print("=" * 72)

    agent = AgentIdentity(
        uid="spiffe://trust.example/agent/demo-agent",
        instance_uid="demo-sess-001",
        session_token="demo.session.token-not-a-real-jwt",
        version="1.0.0",
    )
    chain = AgentStateChain(agent=agent)
    span = CapturingSpan()
    bridge = AgentStateOTelBridge(chain)
    emitted_otel: list[dict[str, Any]] = []
    chain.on_record(lambda rec: emitted_otel.append(rec.to_dict()))

    fake = FakeEngine()
    n_emitted = 0
    with bridge.attach_to(span):
        for batch in fake:
            chain.record(
                engine=ENGINE_IDENTITY,
                batch_sequence_uids=batch["request_ids"],
                tools=ToolInventory.from_schemas(batch["tools"]),
                context=ContextInventory.build(
                    token_ids=batch["token_ids"],
                    sampling_params=batch["sampling_params"],
                    lora_adapters=batch["lora_adapters"],
                ),
            )
            n_emitted += 1

    print(f"\n[1] emitted {n_emitted} inventory records; chain len = {len(chain.records)}")
    for i, rec in enumerate(chain.records):
        print(f"    rec[{i}] seq={rec.forward_pass_seq} "
              f"hash={rec.inventory_hash[:16]}.. prior={rec.prior_inventory_hash[:16]}..")

    print(f"\n[2] span captured {len(span.events)} events named '{EVENT_NAME}'")
    for name, attrs in span.events:
        names = attrs.get("agent.state.tools.names")
        print(f"    {name}: tools={names} hash={attrs.get('agent.state.inventory_hash', '')[:16]}..")

    print("\n[3] chain.verify() on the untampered chain ...")
    print(f"    -> {chain.verify()}  (expected True)")

    # ------------------------------------------------------------------
    # [4] Tamper-evidence: mutate one byte of the 2nd record's serialized
    # form (the tools/schema sub-object) and re-verify. Verify must now
    # return False; on_verify_failure must fire.
    # ------------------------------------------------------------------
    print("\n[4] tampering with tools.tool_names on record[1] ...")
    tampered = chain.records[1]
    tampered_tools = ToolInventory(
        tool_names=tuple(["EVILOVERRIDE"]) + tampered.tools.tool_names,
        tool_schema_hash=tampered.tools.tool_schema_hash,
    )
    # Frozen dataclasses -- rebuild with mutated tools field; this is
    # exactly the surface a malicious actor would target.
    rebuild_kwargs = tampered.to_dict()
    rebuild_kwargs["engine"] = tampered.engine
    rebuild_kwargs["tools"] = tampered_tools
    rebuild_kwargs["context"] = tampered.context
    rebuild_kwargs["batch_sequence_uids"] = tampered.batch_sequence_uids
    from core import AgentStateInventory
    chain.records[1] = AgentStateInventory(**rebuild_kwargs)

    failures: list[tuple[int, str]] = []
    chain.on_verify_failure(lambda idx, r, reason: failures.append((idx, reason)))
    result = chain.verify()
    print(f"    chain.verify() -> {result}  (expected False)")
    print(f"    on_verify_failure fired at indices: {[f[0] for f in failures]}")
    if failures:
        print(f"    first reason: {failures[0][1]}")
    assert result is False, "tampered chain must fail verify"
    assert len(failures) >= 1, "verify_failure must fire on tamper"

    # ------------------------------------------------------------------
    # [5] Re-canonicalizing the original (untampered) record's payload
    # yields the same hash it had before, demonstrating that the chain's
    # tamper-evidence is structural -- the *original* record would have
    # passed; it's the mutation that broke it.
    # ------------------------------------------------------------------
    print("\n[5] reconstructing the original record's hash from its canonical bytes ...")
    from core import _canonical_bytes, _sha256_hex, GENESIS_HASH
    # Walk the chain the way verify() does, against the (mutated) records:
    # the original record at index 0 should still re-hash to its stored
    # value because we never touched index 0.
    rec0 = chain.records[0]
    recomputed0 = _sha256_hex(
        rec0.prior_inventory_hash.encode("ascii"),
        _canonical_bytes(rec0.payload_for_hash()),
    )
    print(f"    rec[0] recomputed hash matches stored: {recomputed0 == rec0.inventory_hash}")
    assert recomputed0 == rec0.inventory_hash, "untampered records must still hash consistently"

    # ------------------------------------------------------------------
    # [6] Render one record as OCSF Agent Inventory Info.
    # ------------------------------------------------------------------
    print(f"\n[6] OCSF Agent Inventory Info [class_uid={CLASS_UID}, type_uid={TYPE_UID}] for rec[0]:")
    ocsf_event = to_ocsf_event(chain.records[0])
    print(json.dumps(ocsf_event, indent=2, default=str))

    assert ocsf_event["class_uid"] == 5050
    assert ocsf_event["category_uid"] == 5
    assert ocsf_event["activity_id"] == 0
    assert ocsf_event["metadata"]["product"]["name"] == "agent-state"
    assert "tools" in ocsf_event and "context" in ocsf_event and "batch" in ocsf_event
    # Verify the Fingerprint-object reuse: chain pointers and sub-object
    # hashes must all be {algorithm_id, algorithm, value} shape.
    inv = ocsf_event["inventory"]
    assert inv["algorithm_id"] == 3 and inv["algorithm"] == "SHA-256"
    assert len(inv["value"]) == 64
    prev_inv = ocsf_event["prev_inventory"]
    assert prev_inv["algorithm_id"] == 3 and prev_inv["value"] == "0" * 64
    tools_fp = ocsf_event["tools"]["schema_fingerprint"]
    assert tools_fp and tools_fp["algorithm_id"] == 3
    ctx_fp = ocsf_event["context"]["context_fingerprint"]
    assert ctx_fp and ctx_fp["algorithm_id"] == 3

    # Agent identity: real OCSF ai_agent object, and the bearer token must
    # never leak into the emitted event -- only its fingerprint should.
    ai_agent = ocsf_event["ai_agent"]
    assert ai_agent["uid"] == agent.uid
    assert ai_agent["instance_uid"] == agent.instance_uid == "demo-sess-001"
    assert ai_agent["version"] == "1.0.0"
    assert ai_agent["token_fingerprint"]["value"] == agent.token_fingerprint()
    assert "session_token" not in json.dumps(ocsf_event), (
        "raw session_token leaked into the OCSF event"
    )
    print(f"\n[7] ai_agent.uid={ai_agent['uid']} "
          f"instance_uid={ai_agent['instance_uid']} "
          f"token_fingerprint={ai_agent['token_fingerprint']['value'][:16]}.. "
          "(raw token confirmed absent from event)")

    print("\n" + "=" * 72)
    print("all assertions passed; demo OK")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
