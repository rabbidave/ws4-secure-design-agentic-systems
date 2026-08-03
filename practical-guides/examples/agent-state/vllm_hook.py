"""
agent_state.vllm_hook
======================

Where the hook actually sits, and why:

vLLM's LLMEngine.step() is the real forward-pass primitive -- each call
runs one model forward pass over whatever the scheduler has batched
together that tick. That's the natural per-forward-pass boundary.

The complication: step() only returns finished/intermediate
RequestOutputs; it doesn't carry the tool schemas or sampling params
that were attached when the request was submitted. Those are only
visible at add_request() time. So this wrapper does two things:

  1. Caches tool schemas + sampling params per request_id at add_request().
  2. At each step(), reads the scheduler's currently-running sequence
     groups to get the actual batch composition, joins that against the
     cache, and emits ONE inventory record per forward pass covering
     every request in that batch.

Tested against the vllm.LLMEngine public surface as of the 0.9.x series.
vLLM's internals (scheduler attribute names, SequenceGroup shape) move
between versions -- the _extract_running_request_ids() and
_extract_tool_schemas() functions below are the two places to check
first if this breaks against a newer vLLM release.

Requires: vllm installed. Not exercised in this sandbox (no GPU / no
vllm install here) -- treat this as a reviewed reference implementation,
not a tested one, and validate against your actual vLLM version before
relying on it.
"""

from __future__ import annotations

from typing import Any, Optional

from core import AgentStateChain, AgentIdentity, EngineIdentity, ToolInventory, ContextInventory, _canonical_bytes


class AgentStateVLLMEngine:
    """
    Wraps a vllm.LLMEngine instance. Use in place of calling the engine
    directly:

        from vllm import LLMEngine, EngineArgs
        from core import AgentIdentity

        raw_engine = LLMEngine.from_engine_args(EngineArgs(model="..."))
        engine = AgentStateVLLMEngine(raw_engine, agent=AgentIdentity(
            uid="spiffe://trust.example/agent/payments-processor",  # stable, from your IdP/control plane
            instance_uid="sess-abc123",                              # this session/run
            session_token=oauth_session_token,                       # bearer token backing this session; see SPEC.md §2.7
        ))

        engine.add_request(request_id, prompt, sampling_params, tools=[...])
        while engine.has_unfinished_requests():
            outputs = engine.step()   # <-- emits an inventory record each call

        engine.chain.verify()          # tamper-check
        from ocsf_mapping import to_ocsf_event
        for rec in engine.chain.records:
            emit_to_ocsf_sink(to_ocsf_event(rec))  # NOT rec.to_dict() -- that carries the raw session_token
    """

    def __init__(self, llm_engine: Any, agent: AgentIdentity):
        self._engine = llm_engine
        self.chain = AgentStateChain(agent=agent)
        self._request_tools: dict[str, list[dict[str, Any]]] = {}
        self._request_lora: dict[str, str] = {}
        self._engine_identity = self._probe_engine_identity()

    # ---- request-scoped metadata capture -------------------------------

    def add_request(
        self,
        request_id: str,
        prompt: Any,
        sampling_params: Any,
        tools: Optional[list[dict[str, Any]]] = None,
        lora_request: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        if tools:
            self._request_tools[request_id] = tools
        if lora_request is not None:
            name = getattr(lora_request, "lora_name", None) or str(lora_request)
            self._request_lora[request_id] = name

        self._engine.add_request(
            request_id, prompt, sampling_params, lora_request=lora_request, **kwargs
        )

    # ---- forward-pass capture -------------------------------------------

    def step(self) -> Any:
        running_ids, batch_tokens = self._snapshot_running_batch()
        outputs = self._engine.step()  # the actual forward pass happens here

        tools_for_batch: list[dict[str, Any]] = []
        lora_for_batch: list[str] = []
        for rid in running_ids:
            tools_for_batch.extend(self._request_tools.get(rid, []))
            lora = self._request_lora.get(rid)
            if lora:
                lora_for_batch.append(lora)

        # Post-step, so the block table reflects whatever this forward pass
        # actually allocated/touched -- same ordering rationale as the
        # llama.cpp hook (state must be snapshotted after the decode call
        # that produced it, not before).
        kv_material = self._snapshot_kv_block_table(running_ids)

        self.chain.record(
            engine=self._engine_identity,
            batch_sequence_uids=running_ids,
            tools=ToolInventory.from_schemas(_dedupe_schemas(tools_for_batch)),
            context=ContextInventory.build(
                token_ids=batch_tokens,
                sampling_params=self._snapshot_sampling_params(running_ids),
                lora_adapters=lora_for_batch,
                kv_state_material=kv_material,
            ),
        )

        for rid in list(self._request_tools):
            if rid not in running_ids:
                self._request_tools.pop(rid, None)
                self._request_lora.pop(rid, None)

        return outputs

    def has_unfinished_requests(self) -> bool:
        return self._engine.has_unfinished_requests()

    # ---- introspection helpers, isolated because they're the version-fragile part ----

    def _probe_engine_identity(self) -> EngineIdentity:
        model_config = getattr(self._engine, "model_config", None)
        vllm_version = "unknown"
        try:
            import vllm  # noqa: F401
            vllm_version = getattr(vllm, "__version__", "unknown")
        except ImportError:
            pass
        return EngineIdentity(
            name="vllm",
            version=vllm_version,
            model_name=getattr(model_config, "model", "unknown"),
            model_revision=getattr(model_config, "revision", None),
            dtype=str(getattr(model_config, "dtype", "") or "") or None,
            quantization=getattr(model_config, "quantization", None),
        )

    def _snapshot_running_batch(self) -> tuple[list[str], list[int]]:
        """
        Reads the scheduler's current running sequence groups. vLLM keeps
        this at engine.scheduler[i].running for pipeline-parallel setups
        (a list of schedulers) or engine.scheduler.running for single-stage;
        this handles both shapes defensively.
        """
        scheduler = getattr(self._engine, "scheduler", None)
        schedulers = scheduler if isinstance(scheduler, list) else [scheduler]

        request_ids: list[str] = []
        token_ids: list[int] = []
        for sched in schedulers:
            if sched is None:
                continue
            for seq_group in getattr(sched, "running", []):
                request_ids.append(getattr(seq_group, "request_id", "unknown"))
                for seq in getattr(seq_group, "get_seqs", lambda: [])():
                    token_ids.extend(getattr(seq, "get_token_ids", lambda: [])())
        return sorted(set(request_ids)), token_ids

    def _snapshot_kv_block_table(self, running_ids: list[str]) -> Optional[bytes]:
        """
        vLLM's actual KV-cache tensors live in GPU-resident paged blocks
        managed internally by the cache/worker layer -- there's no supported
        public API on `LLMEngine` to dump a sequence's raw cache content to
        bytes, and even if there were, raw float tensor bytes aren't
        "portable" in the sense this package cares about (they vary with
        dtype, kernel implementation, and hardware, so two engines holding
        logically-identical state could hash differently for reasons that
        have nothing to do with tamper-evidence).

        What *is* stable and inspectable is the block table: the mapping
        from each running sequence to the physical cache block ids the
        scheduler's BlockManager has allocated it. That's a genuine,
        deterministic identity for "which cache state this forward pass
        touched" -- an analogue of the KV-cache rather than the KV-cache
        itself, same distinction the llama.cpp hook doesn't have to make
        (llama.cpp's session-state API hands back the real bytes).

        Block manager attribute names/shape have moved across vLLM versions
        (V0 scheduler-owned BlockSpaceManager vs V1's KVCacheManager) --
        this is the other place to check first, alongside
        `_snapshot_running_batch`, if this breaks against a newer release.
        Returns None on any lookup failure rather than raising, same as the
        llama.cpp side: a missing block table degrades to "no KV hash this
        call", not a broken hook.
        """
        try:
            scheduler = getattr(self._engine, "scheduler", None)
            schedulers = scheduler if isinstance(scheduler, list) else [scheduler]

            block_table: dict[str, list[int]] = {}
            for sched in schedulers:
                if sched is None:
                    continue
                block_manager = getattr(sched, "block_manager", None)
                if block_manager is None:
                    continue
                for rid in running_ids:
                    blocks = self._extract_block_ids(block_manager, rid)
                    if blocks is not None:
                        block_table[rid] = sorted(blocks)

            if not block_table:
                return None
            return _canonical_bytes({"block_table": block_table})
        except Exception:
            return None

    @staticmethod
    def _extract_block_ids(block_manager: Any, request_id: str) -> Optional[list[int]]:
        """
        Isolated because the accessor shape is the most version-fragile
        part: some releases expose `block_manager.get_block_table(seq)`
        keyed by Sequence, others expose `block_manager.block_tables` keyed
        by request/seq id directly. Try both rather than picking one and
        breaking silently on the other.
        """
        get_table = getattr(block_manager, "get_block_table", None)
        if callable(get_table):
            try:
                table = get_table(request_id)
                return [getattr(b, "block_number", b) for b in table]
            except Exception:
                pass

        tables = getattr(block_manager, "block_tables", None)
        if tables is not None:
            table = tables.get(request_id) if hasattr(tables, "get") else None
            if table is not None:
                return [getattr(b, "block_number", b) for b in table]

        return None

    def _snapshot_sampling_params(self, request_ids: list[str]) -> dict[str, Any]:
        """
        Best-effort: pulls a representative sampling_params dict for hashing.
        If your fleet runs heterogeneous sampling per request within one
        batch, hash per-request instead of batch-level -- this simplified
        version hashes the batch as a set for readability.
        """
        return {"request_ids": request_ids}


def _dedupe_schemas(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for s in schemas:
        key = s.get("name") or str(s)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out
