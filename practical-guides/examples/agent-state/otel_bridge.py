"""
agent_state.otel_bridge
========================

Bridges a core.AgentStateChain to OpenTelemetry. Two emission modes,
matching the OTel spec for events that happen at point-in-time:

  1. Span event -- best choice when a caller already has the parent
     GenAI inference span open and wants the inventory record attached
     as an event on that span. Uses ``span.add_event(name, attributes)``.
     No new span is created.

  2. Log record -- fed to the OTel Logs Bridge via ``logging`` + the
     SDK logs pipeline when there is no span in context (headless
     chains, offline post-processing). The log record carries
     ``event.name = "agent.state.inventoried"`` per the OTel events
     spec (events-as-logs).

Attribute names follow the prefix ``agent.state.*`` so they don't
collide with the OTel GenAI semconv names (``gen_ai.*``), which stay
on the parent span. See SPEC.md §3.3 for the cross-reference table.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Protocol

from core import AgentStateChain, AgentStateInventory


# ---------------------------------------------------------------------------
# Protocols -- duck-typed so this module imports cleanly even when the
# opentelemetry-sdk is not installed.
# ---------------------------------------------------------------------------

class _SpanLike(Protocol):
    def add_event(self, name: str, attributes: Optional[dict[str, Any]] = None) -> None: ...


class _SpanContextLike(Protocol):
    """Anything that can hand us the currently active span when asked."""
    def get_current_span(self) -> Optional[_SpanLike]: ...


# ---------------------------------------------------------------------------
# Attribute assembly
# ---------------------------------------------------------------------------

def attributes_for_event(rec: AgentStateInventory) -> dict[str, Any]:
    """
    Flat dict that maps 1:1 onto the OTel attribute set in SPEC.md §3.2.
    Avoids nesting because OTel attributes are conventionally flat
    with dotted names rather than nested objects (per the OTel
    semantic-convention style guide, attribute names use dot-delimited
    hierarchical names).
    """
    return {
        "agent.state.schema_version": rec.schema_version,
        "agent.state.forward_pass_seq": rec.forward_pass_seq,
        "agent.state.inventory_hash": rec.inventory_hash,
        "agent.state.prior_inventory_hash": rec.prior_inventory_hash,
        "agent.state.session_uid": rec.session_uid,
        "agent.state.engine.name": rec.engine.name,
        "agent.state.engine.version": rec.engine.version,
        "agent.state.tools.names": list(rec.tools.tool_names),
        "agent.state.tools.schema_hash": rec.tools.tool_schema_hash,
        "agent.state.context.prompt_token_count": rec.context.prompt_token_count,
        "agent.state.context.hash": rec.context.context_hash,
        "agent.state.context.sampling_params_hash": rec.context.sampling_params_hash,
        "agent.state.context.lora_adapters": list(rec.context.lora_adapters),
        "agent.state.context.kv_state_hash": rec.context.kv_state_hash,
        "agent.state.batch.request_uids": list(rec.batch_sequence_uids),
    }


EVENT_NAME = "agent.state.inventoried"

# Event body added to OTel log records -- follows the structured-events
# convention laid out in OTEP 0199 / the OTel events spec.
LOG_EVENT_BODY_KEY = "event.name"
LOG_EVENT_BODY_VALUE = EVENT_NAME


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class AgentStateOTelBridge:
    """
    Subscribe once to a chain; emits one OTel span event (or log record)
    per finalized inventory record. Failures inside the OTel emitter do
    not break the chain -- the chain is the source of truth; OTel is a
    projection.

        from otel_bridge import AgentStateOTelBridge
        bridge = AgentStateOTelBridge(chain, logger=my_logger)
        # ...when you have a span hand-off:
        with bridge.attach_to(span):
            chain.record(...)
    """

    def __init__(
        self,
        chain: AgentStateChain,
        *,
        logger: Optional[logging.Logger] = None,
        span_provider: Optional[_SpanContextLike] = None,
    ) -> None:
        self._chain = chain
        self._logger = logger
        self._span_provider = span_provider
        self._active_span: Optional[_SpanLike] = None
        chain.on_record(self._on_record)

    def attach_to(self, span: _SpanLike) -> "_AttachContext":
        """
        Context manager. While active, every finalized record is emitted
        as an event on `span`. Outside the context, records fall back
        to log emission (if a logger was supplied) or are silently
        recorded only on the chain.
        """
        return _AttachContext(self, span)

    # -- internal ----------------------------------------------------

    def _on_record(self, rec: AgentStateInventory) -> None:
        # Prefer the active span if we have one.
        span = self._active_span
        if span is None and self._span_provider is not None:
            try:
                span = self._span_provider.get_current_span()
            except Exception:
                span = None

        if span is not None:
            try:
                span.add_event(EVENT_NAME, attributes=attributes_for_event(rec))
                return
            except Exception:
                # Span emit failed -- fall through to log path so we
                # don't silently lose the record on the OTel side.
                pass

        if self._logger is not None:
            try:
                self._logger.info(
                    "agent.state.inventoried",
                    extra={
                        LOG_EVENT_BODY_KEY: LOG_EVENT_BODY_VALUE,
                        **attributes_for_event(rec),
                    },
                )
            except Exception:
                # Logging also failed -- the chain still has the record;
                # no subscriber is allowed to lose data on the chain.
                pass


class _AttachContext:
    """Tiny inner helper so attach_to() can be a context manager."""

    __slots__ = ("_bridge", "_span")

    def __init__(self, bridge: AgentStateOTelBridge, span: _SpanLike) -> None:
        self._bridge = bridge
        self._span = span

    def __enter__(self) -> _SpanLike:
        self._bridge._active_span = self._span
        return self._span

    def __exit__(self, *exc: Any) -> None:
        self._bridge._active_span = None


# ---------------------------------------------------------------------------
# Standalone setup helper for the logs-only path
# ---------------------------------------------------------------------------

def setup_otel_logging(
    chain: AgentStateChain,
    *,
    service_name: str = "agent-state",
    logger_name: str = "agent_state",
) -> tuple[logging.Logger, "AgentStateOTelBridge"]:
    """
    Configure stdlib `logging` to emit the same structured event
    payload that the span-event path would emit. This is the
    zero-dependency fallback for producers that don't have an active
    span context (headless chains, batch exporters).

    To enable OTLP forwarding from this logger, install the standard
    OpenTelemetry logging packages and add an OTLP log handler:

        from opentelemetry._logs import set_logger_provider
        from opentelemetry.exporter.otlp.proto.http.grpc_exporter import \
            OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider, LogRecordProcessor
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

        provider = LoggerProvider()
        provider.add_log_record_processor(
            BatchLogRecordProcessor(OTLPLogExporter()))
        set_logger_provider(provider)

    Then call this function; the stdlib logger's records will be
    forwarded transparently.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    # Don't add duplicate handlers if setup is called more than once.
    if not any(
        getattr(h, "_agent_state_marker", False) for h in logger.handlers
    ):
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                '{"event":"%(message)s","attrs":%(agent_state_attrs)s}',
                validate=False,
            )
        )
        handler._agent_state_marker = True  # type: ignore[attr-defined]
        logger.addHandler(handler)

    bridge = AgentStateOTelBridge(chain, logger=logger)
    return logger, bridge
