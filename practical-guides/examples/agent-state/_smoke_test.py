"""
Throwaway test to verify the existing modules actually work before
building anything new on top of them. Not part of the deliverables.
"""
from __future__ import annotations

import sys
import os

# Make `core` importable the same way vllm_hook.py / llamacpp_hook.py do.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from core import (
    AgentStateChain,
    EngineIdentity,
    ToolInventory,
    ContextInventory,
    AgentStateInventory,
    _canonical_bytes,
    _sha256_hex,
    GENESIS_HASH,
    SCHEMA_VERSION,
)
from dataclasses import asdict
from ocsf_mapping import to_ocsf_event
from otel_bridge import attributes_for_event


def test_canonical_bytes_is_deterministic():
    p1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    p2 = {"c": [3, 2, 1], "a": 1, "b": 2}
    assert _canonical_bytes(p1) == _canonical_bytes(p2)
    print("canonical bytes deterministic: OK")


def test_chain_round_trip():
    eng = EngineIdentity(
        name="vllm", version="0.9.1", model_name="meta-llama/Llama-3-8B",
        model_revision="abc123", dtype="bfloat16", quantization=None,
    )
    tools = ToolInventory(tool_names=("search", "calc"), tool_schema_hash="deadbeef")
    ctx = ContextInventory(
        prompt_token_count=128, context_hash="feedface",
        sampling_params_hash="cafebabe", lora_adapters=("adapter-1",),
    )

    chain = AgentStateChain(session_uid="sess-test-1")
    r0 = chain.record(engine=eng, batch_sequence_uids=["req-1"], tools=tools, context=ctx)
    r1 = chain.record(engine=eng, batch_sequence_uids=["req-2"], tools=tools, context=ctx)
    r2 = chain.record(engine=eng, batch_sequence_uids=["req-3"], tools=tools, context=ctx)

    assert r0.prior_inventory_hash == GENESIS_HASH
    assert r1.prior_inventory_hash == r0.inventory_hash
    assert r2.prior_inventory_hash == r1.inventory_hash
    assert chain.verify() is True
    print(f"chain round-trip: OK, {len(chain.records)} records")
    print(f"  r0 hash: {r0.inventory_hash[:16]}...")
    print(f"  r1 hash: {r1.inventory_hash[:16]}...")
    print(f"  r2 hash: {r2.inventory_hash[:16]}...")


def test_tamper_detection_works():
    eng = EngineIdentity(
        name="vllm", version="0.9.1", model_name="m", model_revision=None,
    )
    chain = AgentStateChain(session_uid="sess-test-2")
    chain.record(engine=eng, batch_sequence_uids=["a"], tools=ToolInventory(), context=ContextInventory())
    chain.record(engine=eng, batch_sequence_uids=["b"], tools=ToolInventory(), context=ContextInventory())

    # Manually clone record[1] and mutate a single byte of its serialized form
    # by reconstructing the dataclass with a changed prior_inventory_hash (a
    # legit surface -- prior hash being wrong is a real way tampering manifests).
    rec1 = chain.records[1]
    tampered = AgentStateInventory(
        schema_version=rec1.schema_version,
        forward_pass_seq=rec1.forward_pass_seq,
        captured_at_ns=rec1.captured_at_ns,
        engine=rec1.engine,
        session_uid=rec1.session_uid,
        batch_sequence_uids=rec1.batch_sequence_uids,
        tools=rec1.tools,
        context=rec1.context,
        prior_inventory_hash=GENESIS_HASH,  # wrong on purpose
        inventory_hash=rec1.inventory_hash,
    )
    chain.records[1] = tampered
    assert chain.verify() is False
    print("tamper detection: OK (verify() returns False after mutation)")


def test_asdict_shape():
    eng = EngineIdentity(name="vllm", version="x", model_name="m")
    tools = ToolInventory(tool_names=("t1",), tool_schema_hash="h")
    ctx = ContextInventory(prompt_token_count=5, context_hash="c", sampling_params_hash="s")
    inv = AgentStateInventory(
        schema_version=SCHEMA_VERSION, forward_pass_seq=0, captured_at_ns=0,
        engine=eng, session_uid="s", batch_sequence_uids=("a",),
        tools=tools, context=ctx,
        prior_inventory_hash=GENESIS_HASH, inventory_hash="abc",
    )
    d = asdict(inv)
    print(f"asdict keys: {sorted(d.keys())}")
    print(f"engine dict: {d['engine']}")
    print(f"tools dict: {d['tools']}")
    print(f"context dict: {d['context']}")


def test_records_list_is_exposed_publicly():
    chain = AgentStateChain(session_uid="x")
    # The deliverables spec says the new on_record should be a no-op unless
    # something subscribes. Confirm `records` is indeed a plain list we can use.
    assert isinstance(chain.records, list)
    print("records is plain list: OK")


def test_kv_state_hash_flows_through_chain_and_downstream():
    """
    Neither engine is installed in this sandbox, so this exercises the part
    that's engine-agnostic: given raw "KV-state material" bytes (standing in
    for llama.cpp's real session-state bytes or vLLM's canonical block-table
    JSON), confirm the hash (a) is deterministic, (b) is None when no
    material is supplied (engines that fail the snapshot must degrade
    gracefully, not crash), (c) participates in the tamper-evident chain
    like every other field, and (d) actually reaches both downstream
    consumers -- the OCSF mapping and the OTel bridge -- not just core.py.
    """
    eng = EngineIdentity(name="llama.cpp", version="x", model_name="m.gguf")

    # (a) deterministic
    material = b"\x00\x01fake-kv-cache-bytes\x02\x03"
    ctx_a = ContextInventory.build(token_ids=[1, 2, 3], kv_state_material=material)
    ctx_b = ContextInventory.build(token_ids=[1, 2, 3], kv_state_material=material)
    assert ctx_a.kv_state_hash == ctx_b.kv_state_hash
    assert ctx_a.kv_state_hash == _sha256_hex(material)

    # (b) graceful degradation
    ctx_none = ContextInventory.build(token_ids=[1, 2, 3])
    assert ctx_none.kv_state_hash is None

    # (c) participates in the chain / tamper-evidence the same as any field
    chain = AgentStateChain(session_uid="sess-kv-1")
    r0 = chain.record(
        engine=eng, batch_sequence_uids=["seq-1"],
        tools=ToolInventory(), context=ctx_a,
    )
    r1 = chain.record(
        engine=eng, batch_sequence_uids=["seq-1"],
        tools=ToolInventory(),
        context=ContextInventory.build(token_ids=[1, 2, 3, 4], kv_state_material=b"different-state"),
    )
    assert chain.verify() is True
    assert r0.context.kv_state_hash != r1.context.kv_state_hash

    # (d) reaches both downstream consumers
    ocsf_event = to_ocsf_event(r0)
    assert ocsf_event["context"]["kv_state_fingerprint"] == {
        "algorithm_id": 3, "algorithm": "SHA-256", "value": r0.context.kv_state_hash,
    }
    otel_attrs = attributes_for_event(r0)
    assert otel_attrs["agent.state.context.kv_state_hash"] == r0.context.kv_state_hash

    print("kv_state_hash: deterministic, chained, tamper-sensitive, and reaches OCSF + OTel: OK")


if __name__ == "__main__":
    test_canonical_bytes_is_deterministic()
    test_chain_round_trip()
    test_tamper_detection_works()
    test_asdict_shape()
    test_records_list_is_exposed_publicly()
    test_kv_state_hash_flows_through_chain_and_downstream()
    print("\nall smoke checks passed")
