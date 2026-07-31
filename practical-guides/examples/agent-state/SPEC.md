# Agent Inventory Info — Instrumentation Specification

**Status:** reference spec · schema version `agent-state/1.0`
**Scope:** a per-forward-pass *inventory* record for LLM agents served by vLLM or llama-cpp-python, emitted at the moment of `LLMEngine.step()` / `llama_decode()`, with a SHA-256 hash chain over successive inventories.

---

## 1. Mission

`agent-state` captures, exactly once per forward pass, a hashable snapshot of what the model *had available to it* at the moment it produced a step of output: the tool schemas bound to the conversation, the composition of the scheduled batch, the token-id hash of the live context, the running sampling params, and the active LoRA adapters. It deliberately avoids saying anything about what the model *did* — no actor intent, no permitir/deny decision, no request/response pair. It is an **inventory**, not an **activity**.

That distinction is why this event lives in the OCSF **Discovery** category next to `Device Inventory Info [5001]`, `User Inventory Info [5003]`, `Software Inventory Info [5020]`, `Cloud Resources Inventory Info [5023]` — and explicitly **not** in `API Activity [6003]` (Application Activity, Category 6). Forcing `agent-state` into API Activity would require manufacturing an actor, an action, and an authorization outcome none of which the model's forward pass actually produces.

### 1.1 Continuity: two chains, one mechanism

`agent-state` ships one record type today, `Agent Inventory Info [5050]`, this spec. A second is proposed and tracked separately: `Agent Tool Activity`, an Application Activity-category class for the T12 audit-log gap (which tool was invoked, with what argument digest, in what session — see [cosai-oasis/ws4-secure-design-agentic-systems#155](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/155)). Inventory and Activity answer different questions (§2.1) and neither substitutes for the other. But they are not two different trust models bolted together — both chain the same way, and both have to clear the same three portability axes before either is trustworthy:

- **Implementation-agnostic.** The hashing boundary sits beneath the engine, not inside it. vLLM's `LLMEngine.step()` and llama.cpp's `llama_decode()` are the two boundaries this spec hooks today (§6). A third engine gets the same treatment by finding its own per-forward-pass primitive, not by special-casing the hash. An activity record would hook the engine's tool-dispatch boundary the same way.
- **Protocol-agnostic.** The hash is drawn beneath the wire envelope, not the transport that carried it there. `ToolInventory.from_schemas()` hashes the unwrapped tool definition, whether it arrived as an MCP `tools/list` JSON-RPC frame, an OpenAI/Anthropic function-calling payload, or an A2A agent card. An activity record would draw the same boundary beneath whichever transport reports the invocation.
- **Environment-agnostic.** `core.py` has zero third-party dependencies (`hashlib`, `json`, `dataclasses`, stdlib only). Canonical bytes are identical whether recomputed on a GPU cluster, a laptop, or an edge device, so a verifier's result doesn't depend on where it verifies.

An inventory chain that fails any of these three is a convenience log with an OCSF label on it, not an attestation. The activity chain, once it exists, inherits `core._canonical_bytes`/`_sha256_hex` and the chain-by-prior-hash pattern (§5) rather than a parallel mechanism that happens to look similar — same portability guarantees, applied to a different event shape.

## 2. OCSF mapping — `Agent Inventory Info [5050]`

Proposed new class under **Category 5 (Discovery)**. UID `5050` is the next free slot in the standard 50xx Discovery range (5040, the live-evidence class, is currently the highest in active use).

### 2.1 Why `API Activity [6003]` is the wrong home

| `agent-state` field         | API Activity would require                        | Actual agent-state shape                               |
|-----------------------------|----------------------------------------------------|--------------------------------------------------------|
| actor                       | one or more `actor` objects (user / process)      | none — the model has no principal identity             |
| action / operation          | `activity_id` ∈ {Create, Read, Update, Delete}     | none — the forward pass performs no permit/deny action |
| request / response pair     | `request` and `response` objects                  | one record, no request/response symmetry               |
| `dst_endpoint` / API call   | HTTP/RPC endpoint                                  | tensor matmuls; no API surface                        |
| `auth_decision`             | nullable but scoped to allow/deny                   | not applicable                                         |

The agent-state record is the model's surface-area inventory taken once per forward pass. Forcing it through API Activity would require filling fields with synthetic values, which is exactly the mapping pattern OCSF warns against. **Discovery Inventory Info is the right precedent**: `Device Inventory Info` and `User Inventory Info` are point-in-time snapshots of a managed surface, no actor activity involved.

### 2.2 `Agent Inventory Info [5050]` attribute table

All `*_hash` and `*_fingerprint` attributes use the **existing OCSF `Fingerprint` object** (observable_id 30) — see §2.6. That object already exists with `{algorithm_id, algorithm, value}` and is referenced by `File.hashes`, `Software Package.hash`, `Container.hash`, `Digital Certificate.fingerprints`, and `Script.hashes`. We do not invent a new hash type.

| #  | Attribute                              | OCSF type               | Notes                                                                            |
|----|----------------------------------------|-------------------------|----------------------------------------------------------------------------------|
| 1  | `class_uid`                            | int                     | constant `5050`                                                                  |
| 2  | `category_uid`                         | int                     | constant `5` (Discovery)                                                         |
| 3  | `activity_id`                          | int                     | constant `0` (Unknown) — intentional: not an activity class                     |
| 4  | `type_uid`                             | int                     | `505000`                                                                          |
| 5  | `class_name`                           | string_t                | `"Agent Inventory Info"`                                                          |
| 6  | `category_name`                        | string_t                | `"Discovery"`                                                                     |
| 7  | `activity_name`                        | string_t                | `"Unknown"`                                                                       |
| 8  | `type_name`                            | string_t                | `"Agent Inventory Info:Unknown"`                                                 |
| 9  | `agent_uid`                            | string_t                | opaque engine identity (e.g. `"vllm://Qwen2.5-7B-Instruct"`); hashed out as `engine.name + "://" + engine.model_name` |
| 10 | `agent_type`                           | string_t (enum)         | `"llm_forward_pass"`                                                              |
| 11 | `engine`                               | string_t                | `engine.name` (vLLM or llama.cpp)                                                  |
| 12 | `engine_version`                       | string_t                | `engine.version`                                                                  |
| 13 | `model`                                | string_t                | `engine.model_name`                                                               |
| 14 | `model_revision`                       | string_t (nullable)     | weights hash or HF commit                                                          |
| 15 | `instrumentation_library_name`         | string_t                | constant `"agent-state"`                                                          |
| 16 | `instrumentation_library_version`      | string_t                | `"1.0"`                                                                          |
| 17 | `session_uid`                          | string_t                | identifies the chat/conversation this forward pass belongs to                       |
| 18 | `forward_pass_seq`                     | long                    | monotonic per session                                                              |
| 19 | `captured_at`                          | timestamp_t             | `captured_at_ns // 1e9` (seconds since epoch)                                       |
| 20 | `prev_inventory`                       | Fingerprint             | `{algorithm_id: 3, algorithm: "SHA-256", value: <prior hash>}`; `value = "0"*64` for the chain root |
| 21 | `inventory`                            | Fingerprint             | `{algorithm_id: 3, algorithm: "SHA-256", value: sha256(prev.value || canonical(payload))}` |
| 22 | `tools` (object)                       | AgentToolsInfo          | see §2.3                                                                          |
| 23 | `context` (object)                     | AgentContextInfo        | see §2.3                                                                          |
| 24 | `batch` (object)                       | AgentBatchInfo          | see §2.3                                                                          |
| 25 | `metadata` (object)                    | Metadata                | standard OCSF metadata envelope; `metadata.product.name = "agent-state"`, `metadata.product.version = "1.0"` |

The chain still needs a top-level pointer attribute (we use `prev_inventory`), not a position inside the `Fingerprint` object — the `Fingerprint` object has no notion of `prior`, and that's correct: it models a single digest, not chain topology. The chain pointer lives on the event class; the digest value lives in the Fingerprint object.

### 2.3 Embedded objects

**AgentToolsInfo** (`agent_state.tools`):
- `names` : string_t[] — sorted tool names
- `schema_fingerprint` : **Fingerprint** — `{algorithm_id: 3, algorithm: "SHA-256", value: <hash>}` over canonical JSON of the full tool schema list

**AgentContextInfo** (`agent_state.context`):
- `prompt_token_count` : int (nullable)
- `context_fingerprint` : **Fingerprint** — over canonical JSON `{"tokens": [...]}`
- `sampling_params_fingerprint` : **Fingerprint** — over canonical JSON of the sampling params
- `lora_adapters` : string_t[] — sorted LoRA adapter names
- `kv_state_fingerprint` : **Fingerprint** (nullable) — over the engine's actual post-decode KV-cache state, not just the inputs that produced it. Source material differs per engine and is documented in §3.5; both paths funnel through the same `_sha256_hex` in `core.py`, so there is still exactly one digest function in the package.

**AgentBatchInfo** (`agent_state.batch`):
- `request_uids` : string_t[] — sorted request ids co-scheduled in this forward pass

All sub-object hashes are the same `Fingerprint` object as the chain pointers. This is purely additive for downstream parsers: a consumer that understands `File.hashes` understands `agent_state.context.context_fingerprint` without bespoke code.

### 2.4 Optical alignment with siblings

Side-by-side comparison with `User Inventory Info [5003]`:

| field                  | User Inventory Info            | Agent Inventory Info                  |
|------------------------|--------------------------------|---------------------------------------|
| `*_uid`                | `user_uid`                     | `agent_uid`                           |
| `*_type`               | `user_type`                    | `agent_type`                          |
| inventory record id    | `record_uid`                   | `inventory_hash` (hash → record id) |
| chained prev ref       | —                              | `prev_inventory_hash`                 |
| enumeration timestamp  | `captured_at`                  | `captured_at`                         |
| feature set            | `account`, `groups`, `credentials` | `tools`, `context`, `batch`             |
| `metadata.product.*`   | yes                            | yes                                   |

Shape parity: both are *Inventory Info* — point-in-time snapshots of an addressable surface, no actor activity, no policy decision.

### 2.5 Other Discovery siblings (precedent)

- `Device Inventory Info [5001]` — point-in-time inventory of a device.
- `User Inventory Info [5003]` — point-in-time inventory of a user account and its groups.
- `Software Inventory Info [5020]` — inventory of installed software.
- `Cloud Resources Inventory Info [5023]` — inventory of cloud resources.
- `Live Evidence Info [5040]` — point-in-time snapshot of observed state used for forensic reconstruction. **Closest philosophical sibling**: `agent-state` is exactly a live-evidence snapshot of the model's addressable surface at decode time.

### 2.6 Reuse of the existing `Fingerprint` object

We avoid inventing a new hash type by reusing OCSF's existing **`Fingerprint` object (observable_id 30)**, already referenced by `File.hashes`, `Container.hash`, `Software Package.hash`, `Software Component.hash`, `Digital Certificate.fingerprints`, `Script.hashes`, `HASSH.fingerprint`, and `Identity Provider.fingerprint`. Its schema is:

| Field           | Type    | Requirement | Notes                                              |
|-----------------|---------|-------------|----------------------------------------------------|
| `algorithm_id`  | int     | required    | enum: `0`=Unknown, `1`=MD5, `2`=SHA-1, `3`=**SHA-256**, `4`=SHA-512, `5`=CTPH, `6`=TLSH, `7`=quickXorHash, `99`=Other |
| `algorithm`     | string  | optional    | string sibling of `algorithm_id`; populated when `algorithm_id=99` (Other) or simply mirrored for human readability |
| `value`         | string  | required    | the digest (hex); for SHA-256, 64 lowercase hex chars |

**Mapping from the v1 shape**: every former bare `*_hash: hash_t` attribute is now `*_<name>: Fingerprint` with `{algorithm_id: 3, algorithm: "SHA-256", value: <the hex digest>}`. The chain semantics (`prev_inventory.value`) sit on the event class because the `Fingerprint` object models a single digest and has no built-in notion of `prior`.

**Why this matters operationally**: SIEMs that already parse `File.hashes` (Splunk ES, Elastic SIEM, Microsoft Sentinel, Devo, IBM QRadar) get `agent_state.inventory.value` for free in their existing hash-field extractors — no custom OCSF extension needed to start correlating inventory-level hashes with file hashes or certificate fingerprints on the same query plane.

**Why the chain still needs the top-level `prev_inventory` pointer**: `Fingerprint` is a flat `{algorithm, value}` pair; it has no slot for the predecessor's value. A hash chain needs both ends. We could have introduced a new `HashChain` object, but that would inflate the surface — instead, the event class itself carries `prev_inventory` and `inventory` both as Fingerprint instances, and the chain is implied by the convention `rec[i].prev_inventory.value == rec[i-1].inventory.value` (verified by `AgentStateChain.verify()`).

## 3. OpenTelemetry bridge

### 3.1 Event identity

- Event name: `agent.state.inventoried`
- Topology: the event attaches to the parent **inference span** as a span event (not a new span). The parent span carries the OTel GenAI semconv vocabulary (`gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.conversation.id`, `gen_ai.usage.input_tokens`); the agent-state event adds the inventory vocabulary on top.

### 3.2 Event attribute set

| Attribute                                          | OTel value type   | Source field                                                |
|----------------------------------------------------|-------------------|-------------------------------------------------------------|
| `agent.state.schema_version`                        | STRING            | `AgentStateInventory.schema_version`                       |
| `agent.state.forward_pass_seq`                      | INT               | `forward_pass_seq`                                          |
| `agent.state.inventory_hash`                        | STRING            | `inventory_hash`                                           |
| `agent.state.prior_inventory_hash`                  | STRING            | `prior_inventory_hash`                                      |
| `agent.state.session_uid`                          | STRING            | `session_uid`                                                |
| `agent.state.engine.name`                           | STRING            | `engine.name`                                               |
| `agent.state.engine.version`                        | STRING            | `engine.version`                                            |
| `agent.state.tools.names`                           | STRING_ARRAY      | `tools.tool_names`                                          |
| `agent.state.tools.schema_hash`                     | STRING            | `tools.tool_schema_hash`                                    |
| `agent.state.context.prompt_token_count`            | INT (nullable)    | `context.prompt_token_count`                                |
| `agent.state.context.hash`                          | STRING            | `context.context_hash`                                      |
| `agent.state.context.sampling_params_hash`         | STRING            | `context.sampling_params_hash`                              |
| `agent.state.context.lora_adapters`                 | STRING_ARRAY      | `context.lora_adapters`                                     |
| `agent.state.context.kv_state_hash`                 | STRING (nullable) | `context.kv_state_hash` — see §3.4 for per-engine source material |
| `agent.state.batch.request_uids`                    | STRING_ARRAY      | `batch_sequence_uids`                                       |

### 3.3 Cross-reference with OTel `gen_ai.*` semconv

| `gen_ai.*` semconv                | Stays on parent span? | Rationale                                                  |
|-----------------------------------|-----------------------|-------------------------------------------------------------|
| `gen_ai.request.model`             | yes                   | request-level fact, not forward-pass-level                  |
| `gen_ai.conversation.id`          | yes                   | equals `agent.state.session_uid`; recommended to set both   |
| `gen_ai.operation.name`            | yes                   | chat / generate_content / text_completion                   |
| `gen_ai.usage.input_tokens`        | yes                   | lives on the *response* span, not on every forward pass       |

The `agent.state.session_uid` carries the same value as `gen_ai.conversation.id` — the bridge should set both to make the cross-join trivial in any OTLP consumer.

### 3.4 KV-state fingerprint source material, per engine

The `inventory`/`prev_inventory` fingerprints (§2.2) cover the *inputs* to a
forward pass — tool schemas, context tokens, sampling params. They say
nothing about the engine's actual cache state after decoding, which is a
distinct claim: two forward passes can share identical inputs and still
diverge in cache state if something below the input layer misbehaves.
`kv_state_fingerprint` closes that gap, but the two reference engines expose
fundamentally different material for it:

| Engine | What gets hashed | Why |
|---|---|---|
| **llama.cpp** | Raw bytes from the session-state API (`llama_state_get_data` / `llama_copy_state_data`, whichever the installed binding exposes), snapshotted immediately after `llama_decode()` returns | llama.cpp exposes a genuine, serializable snapshot of KV-cache + RNG state — this is the real thing, not a proxy |
| **vLLM** | Canonical JSON over the paged-attention block table (`{request_id: sorted(block_ids)}`) for the running sequences, snapshotted immediately after `LLMEngine.step()` returns | vLLM's raw KV tensors live in GPU-resident paged blocks with no supported public dump API, and raw float bytes wouldn't be portable across dtype/kernel/hardware anyway. The block table is the closest stable, deterministic analogue: *which* cache state this pass touched, not the tensor content itself |

Both paths snapshot **after** the forward-pass call that mutates the cache,
not before — the input-inventory fields don't change as a result of the
decode call itself, so their pre/post ordering doesn't matter, but the whole
point of a KV-cache fingerprint is that it reflects what decoding produced.

Known cost (llama.cpp path): the session-state API returns the *entire*
context's state, not a per-call delta, so hashing it every decode is
O(context length) work per forward pass. Fine for the reference
implementation; a production deployment on long-running sessions should move
to the per-sequence state API (`llama_state_seq_get_size` /
`llama_state_seq_get_data`) once a specific sequence is chosen to fingerprint.

### 3.5 Logs-event fallback

For consumers without a span context (headless chains, batch post-processing), the same payload is emitted as an OTel **log record** with `event.name = "agent.state.inventoried"`. This is the OTel-spec-compliant way to emit a discrete event outside a span.

## 4. Canonicalization

` inventory_hash` covers `sha256(ascii(prev_inventory_hash) || canonical(payload))`. Canonicalization is performed by `core._canonical_bytes`, which is `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")`.

Two logically-identical payloads (same keys, same values, regardless of dict ordering or whitespace) produce identical bytes. Both bridges reuse `core._canonical_bytes` — there is no second serializer anywhere in the package, and no bridge computes its own digest. If a consumer wishes to hash an event after transport, it must round-trip the JSON through `json.loads` then `_canonical_bytes(key="...")` rather than permuting.

## 5. Tamper-evidence chain

### 5.1 Semantics

```
rec[0].prior_inventory_hash = "0" * 64
rec[i].prior_inventory_hash = rec[i-1].inventory_hash
rec[i].inventory_hash = sha256(ascii(prior) || canonical(payload(prior, this_record)))
```

Payload fed into the hash excludes `inventory_hash` itself (`AgentStateInventory.payload_for_hash()` strips the field). Every other field is in scope: `schema_version`, `forward_pass_seq`, `captured_at_ns`, full engine identity, `session_uid`, sorted `batch_sequence_uids`, full `tools` and `context`, and `prior_inventory_hash`.

### 5.2 Verify semantics (`AgentStateChain.verify()`)

Walks the chain from genesis, recomputing each hash, and returns True iff every `prior_inventory_hash` and every `inventory_hash` matches. Any byte-level tampering of `tools`, `context`, `batch_sequence_uids`, or `engine` of record *k* will:
1. fail the per-record `inventory_hash` check at record *k*,
2. break the prior-pointer at record *k+1*, since its `prior_inventory_hash` was computed against the un-tampered *k*.

So one edit invalidates the rest of the chain — same shape as a transparency log, no external log service required for session-level integrity.

### 5.3 Subscribers

`AgentStateChain.on_record(callback)` fires after each finalized record is appended (post-`_on_record` subscribers see hashes already filled in). `on_verify_failure(callback)` fires once per tampered record on the next `verify()` call — subscribers receive `(idx, record, reason)`. Existing call sites that do not subscribe are unchanged: notifications only fire if something subscribes.

## 6. Emission point — and why only there

```
vLLM:           LLMEngine.step()             ← one per scheduler tick
                (AgentStateVLLMEngine wraps the engine)

llama.cpp:      llama_decode(ctx, batch)     ← the only per-token-primitive
                (AgentStateLlamaCpp monkey-patches this FFI call)
```

Hooks placed above these boundaries (e.g. wrapping `LLM.generate()`, `Llama.create_chat_completion()`) miss internal decode calls made by beam search, speculative decoding, and batched continuation. Hooks placed below them (e.g. inside the CUDA kernel) lose visibility into tool schemas because that fact never reaches the tensor layer. The current boundary is the narrowest scope where both *what was bound* and *a forward pass happened* are simultaneously observable.

## 7. What this spec does *not* claim

- Not a substitute for the agent-application API activity log (which still belongs in API Activity). An orchestrator that makes a routing decision between agents emits API Activity; the engine that decodes the next token emits Agent Inventory.
- Not a transparency log service — for cross-host tamper-evidence you should anchor the chain tips externally, the same way you would trust-anchor any local chain.
- Not a model-output provenance signal. What the model *said* is downstream of these records but not part of them. Joint replay ("which tools were available at the moment this completion was produced?") is the primary investigative use.

## 8. File index

| File                        | Role                                                            |
|-----------------------------|-----------------------------------------------------------------|
| `core.py`                  | canonical record + hash chain (engine-agnostic)                  |
| `vllm_hook.py`             | hook wrapping `vllm.LLMEngine.step()`                            |
| `llamacpp_hook.py`         | hook patching `llama_decode()` + context propagation             |
| `ocsf_mapping.py`          | `AgentStateInventory` → `Agent Inventory Info [5050]` converter  |
| `otel_bridge.py`           | chain subscriber → OTel span event / log record                  |
| `demo.py`                  | stdlib-only demo + tamper-evidence check                        |
| `diagram.mmd`              | Mermaid diagrams (forward-pass boundary, assembly, sink fan-out) |
