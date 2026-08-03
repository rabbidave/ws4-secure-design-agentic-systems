"""
agent_state.llamacpp_hook
==========================

Where the hook actually sits, and why:

Unlike vLLM, llama.cpp's core has no concept of "requests" or "tools" --
that's all built at the Python-binding layer (llama-cpp-python) or the
server layer, on top of a C library whose only real primitive is
llama_decode(ctx, batch): the actual forward pass. Any hook placed above
that (e.g. wrapping Llama.create_chat_completion) would miss internal
decode calls made by beam search / speculative decoding / batched
continuations; any hook placed at llama_decode() has no visibility into
tool schemas, because those never reach the C layer.

So this uses context propagation: a contextvars.ContextVar carries the
current call's tool schemas + session id, set by a context manager around
the high-level call the caller already makes, and read by the patched
llama_decode() the moment it actually fires. This keeps the two facts --
"what tools were bound" and "a forward pass just happened" -- correctly
joined even though the C layer never sees the first fact.

Requires: llama-cpp-python installed. Not exercised in this sandbox (no
llama-cpp-python install, no GPU/CPU model weights here) -- reviewed
reference implementation, not a tested one. Validate the llama_decode
patch point against your installed llama-cpp-python version; the FFI
binding module path (`llama_cpp.llama_cpp.llama_decode` vs.
`llama_cpp.llama_decode`) has moved before across releases.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Optional

from core import AgentStateChain, AgentIdentity, EngineIdentity, ToolInventory, ContextInventory

_call_context: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar(
    "agent_state_call_context", default=None
)


class AgentStateLlamaCpp:
    """
    Wraps a llama_cpp.Llama instance and patches the module-level FFI
    decode call so every actual forward pass gets an inventory record,
    joined against whatever tool/session context was active when it fired.

        from llama_cpp import Llama
        from core import AgentIdentity

        raw = Llama(model_path="model.gguf")
        engine = AgentStateLlamaCpp(raw, agent=AgentIdentity(
            uid="spiffe://trust.example/agent/payments-processor",  # stable, from your IdP/control plane
            instance_uid="sess-abc123",                              # this session/run
            session_token=oauth_session_token,                       # bearer token backing this session; see SPEC.md §2.7
        ))

        with engine.bind(tools=[...], session_seq_uid="seq-1"):
            result = raw.create_chat_completion(messages=[...], tools=[...])

        engine.chain.verify()
        from ocsf_mapping import to_ocsf_event
        for rec in engine.chain.records:
            emit_to_ocsf_sink(to_ocsf_event(rec))  # NOT rec.to_dict() -- that carries the raw session_token
    """

    def __init__(self, llama_instance: Any, agent: AgentIdentity):
        self._llama = llama_instance
        self.chain = AgentStateChain(agent=agent)
        self._engine_identity = self._probe_engine_identity()
        self._patch_decode()

    @contextmanager
    def bind(
        self,
        tools: Optional[list[dict[str, Any]]] = None,
        session_seq_uid: str = "seq-1",
        lora_adapters: Optional[list[str]] = None,
    ):
        token = _call_context.set(
            {
                "tools": tools or [],
                "session_seq_uid": session_seq_uid,
                "lora_adapters": lora_adapters or [],
            }
        )
        try:
            yield
        finally:
            _call_context.reset(token)

    # ---- the actual hook ------------------------------------------------

    def _patch_decode(self) -> None:
        try:
            import llama_cpp
        except ImportError as e:
            raise RuntimeError(
                "llama-cpp-python is not installed; AgentStateLlamaCpp "
                "cannot patch llama_decode without it."
            ) from e

        # The FFI binding has lived at both llama_cpp.llama_decode and
        # llama_cpp.llama_cpp.llama_decode depending on version -- check
        # both, patch whichever exists, and keep a reference to unpatch.
        target_module = llama_cpp
        if not hasattr(target_module, "llama_decode") and hasattr(target_module, "llama_cpp"):
            target_module = llama_cpp.llama_cpp

        if not hasattr(target_module, "llama_decode"):
            raise RuntimeError(
                "Could not locate llama_decode on the installed llama_cpp "
                "module -- binding layout has changed; update the patch "
                "point in AgentStateLlamaCpp._patch_decode()."
            )

        self._original_decode = target_module.llama_decode
        self._patched_module = target_module

        def patched_decode(ctx, batch):
            token_ids = _extract_batch_token_ids(batch)
            ctx_info = _call_context.get()
            # Decode first: the KV-cache state we want to fingerprint is the
            # *result* of this call, not the state going into it. Emitting
            # before decode (as an earlier version of this hook did) would
            # capture the input inventory correctly but pair it with the
            # cache state from the *previous* forward pass.
            result = self._original_decode(ctx, batch)
            kv_bytes = self._snapshot_kv_state_bytes(ctx)
            self._emit_record(token_ids, ctx_info, kv_bytes)
            return result

        target_module.llama_decode = patched_decode

    def unpatch(self) -> None:
        if hasattr(self, "_patched_module"):
            self._patched_module.llama_decode = self._original_decode

    # ---- record emission -------------------------------------------------

    def _emit_record(
        self,
        token_ids: Optional[list[int]],
        ctx_info: Optional[dict[str, Any]],
        kv_bytes: Optional[bytes],
    ) -> None:
        ctx_info = ctx_info or {}
        tools = ctx_info.get("tools") or []
        seq_uid = ctx_info.get("session_seq_uid", "seq-1")
        lora_adapters = ctx_info.get("lora_adapters") or []

        self.chain.record(
            engine=self._engine_identity,
            batch_sequence_uids=[seq_uid],
            tools=ToolInventory.from_schemas(tools),
            context=ContextInventory.build(
                token_ids=token_ids,
                sampling_params=self._current_sampling_params(),
                lora_adapters=lora_adapters,
                kv_state_material=kv_bytes,
            ),
        )

    def _snapshot_kv_state_bytes(self, ctx: Any) -> Optional[bytes]:
        """
        Grab the actual post-decode session state -- KV-cache contents plus
        RNG state -- as raw bytes, so the fingerprint covers what the engine
        really holds rather than just the inputs that produced it.

        Prefers the high-level `Llama.save_state()` API (part of
        llama-cpp-python's public Python surface, so it moves less often
        than the raw ctypes binding names). Falls back to the ctypes-level
        state API directly, checking both naming generations the same way
        `_patch_decode` already checks both `llama_decode` locations --
        `llama_state_get_size`/`llama_state_get_data` (current) and
        `llama_get_state_size`/`llama_copy_state_data` (pre-rename,
        still present in many installed versions for back-compat).

        Known cost: this snapshots the *entire* session state on every
        decode call, not just the delta -- fine for the reference/demo
        path, but on a long-running session this is O(context length) work
        per forward pass. A production deployment should switch to the
        per-sequence state API (`llama_state_seq_get_size` /
        `llama_state_seq_get_data`) once you've picked which sequence(s) in
        the batch you actually need fingerprinted, rather than hashing the
        whole context on every step.

        Returns None (rather than raising) on any failure -- a missing or
        renamed binding should degrade the record to "no KV hash this call",
        not take down the whole hook.
        """
        try:
            saved = self._llama.save_state()
            state_bytes = getattr(saved, "llama_state", None)
            if state_bytes is not None:
                return bytes(state_bytes)
        except Exception:
            pass

        try:
            import ctypes
            import llama_cpp

            module = llama_cpp
            if not hasattr(module, "llama_state_get_size") and hasattr(module, "llama_cpp"):
                module = llama_cpp.llama_cpp

            if hasattr(module, "llama_state_get_size") and hasattr(module, "llama_state_get_data"):
                size = module.llama_state_get_size(ctx)
                buf = (ctypes.c_uint8 * size)()
                module.llama_state_get_data(ctx, buf, size)
                return bytes(buf)

            if hasattr(module, "llama_get_state_size") and hasattr(module, "llama_copy_state_data"):
                size = module.llama_get_state_size(ctx)
                buf = (ctypes.c_uint8 * size)()
                module.llama_copy_state_data(ctx, buf)
                return bytes(buf)
        except Exception:
            pass

        return None

    def _current_sampling_params(self) -> dict[str, Any]:
        # llama-cpp-python stores the last-used sampling params on the
        # Llama instance between calls to sample(); surface what's
        # actually available rather than guessing at attribute names
        # that vary by version.
        params = getattr(self._llama, "last_sampling_params", None)
        return dict(params) if params else {}

    def _probe_engine_identity(self) -> EngineIdentity:
        import llama_cpp

        version = getattr(llama_cpp, "__version__", "unknown")
        model_path = getattr(self._llama, "model_path", "unknown")
        return EngineIdentity(
            name="llama.cpp",
            version=version,
            model_name=model_path,
            model_revision=None,  # populate from GGUF metadata / file hash if you track it
            dtype=None,
            quantization=None,
        )
