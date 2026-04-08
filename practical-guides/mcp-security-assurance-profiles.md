# MCP Security Assurance Profiles

Contributors: [Nik Kale](mailto:nikkal@cisco.com)

**Status:** Draft for review
**Related issues:** [#36](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/36), [#24](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/24), [#63](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/63)
**Builds on:** MCP Security Whitepaper V1 (Sections 3.x, Appendix 6.1), MCP Specification revisions ([2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18), [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25))

---

## Table of Contents

1. [Purpose](#purpose)
2. [Level Definitions](#level-definitions)
3. [Control Requirements by Level](#control-requirements-by-level)
   - [1. Identity and Authentication](#1-identity-and-authentication)
   - [2. Authorization and Delegation](#2-authorization-and-delegation)
   - [3. Transport and Network Security](#3-transport-and-network-security)
   - [4. Isolation and Sandboxing](#4-isolation-and-sandboxing)
   - [5. Logging and Observability](#5-logging-and-observability)
   - [6. Supply Chain and Lifecycle](#6-supply-chain-and-lifecycle)
   - [7. Tool Definition, Input, and Output Integrity](#7-tool-definition-input-and-output-integrity)
   - [8. Session and Discovery Security](#8-session-and-discovery-security)
4. [Threat Coverage Summary](#threat-coverage-summary)
5. [Deployment Pattern Mapping](#deployment-pattern-mapping)
6. [Applying Profiles in Practice](#applying-profiles-in-practice)
7. [Emerging Standards](#emerging-standards)
8. [Open Questions](#open-questions)

---

## Purpose

The MCP Security Whitepaper defines twelve threat categories and their mitigations. A flat list of controls, however, does not help practitioners determine which controls apply to their specific deployment. A sandbox experiment and a multi-tenant production system do not share the same threat surface. Applying uniform requirements causes friction: sandbox experiments stall under heavy compliance burdens, while production systems carry hidden risk due to under-investment.

Assurance profiles map specific security controls to specific deployment contexts. This document defines four assurance levels for MCP deployments. Each level specifies concrete control requirements across eight security dimensions, maps back to the MCP-T1 through MCP-T12 threat categories from the whitepaper (with cross-references to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)), and aligns with the deployment patterns in Appendix 6.1. The [2026 MCP roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/) identifies enterprise readiness as a top priority; these profiles provide the security dimension of that effort.

The level numbering follows conventions used in frameworks like [SLSA](https://slsa.dev/spec/v1.0/): higher numbers indicate stronger assurance, and levels are cumulative (Level 3 includes everything in Level 2). Unlike [NIST SP 800-63](https://pages.nist.gov/800-63-4/sp800-63.html), which separates assurance across identity proofing (IAL), authentication (AAL), and federation (FAL), these profiles combine multiple security dimensions into a single deployment-oriented tier for operational simplicity.

## Level Definitions

| Level | Alias | Intended Use | Trust Assumptions |
| :---- | :---- | :---- | :---- |
| Level 1 | Sandbox | Local development, single-user experiments, proof-of-concept work | Single user, no sensitive data, failures are recoverable. No access to production credentials or live data. |
| Level 2 | Internal | Internal enterprise deployments, team-shared environments, staging | Authenticated users within an organization. Moderate blast radius. Incidents must be diagnosable after the fact. |
| Level 3 | Production | Production workloads handling sensitive or business-critical data | Active threat surface. Data loss or unauthorized access has material business impact. Full auditability required. |
| Level 4 | Regulated | Multi-tenant platforms, adversarial environments, regulatory scope | Active adversaries assumed. Regulatory audit obligations. Strong tenant isolation and workload attestation required. |

## Control Requirements by Level

### 1. Identity and Authentication

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| MCP client-server authentication | Implicit (local process via stdio) | MUST: [OAuth 2.1](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) with PKCE for all remote server connections | MUST: OAuth 2.1 with PKCE, short-lived credentials, and [Client ID Metadata Documents](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-registration) | MUST: OAuth 2.1 with PKCE, short-lived credentials, and enterprise-managed authorization where applicable |
| Agent identity | Not required | SHOULD: agents registered in a local inventory with unique identifiers | MUST: standardized workload identity (e.g., [SPIFFE / SPIRE](https://spiffe.io/) SVIDs) tied to specific code versions | MUST: workload identity with cryptographic attestation verifying the execution environment matches the declared manifest |
| User identity propagation | Not applicable | If acting on behalf of a user, SHOULD: preserve subject identity to downstream authorization components | MUST: [token exchange](https://datatracker.ietf.org/doc/html/rfc8693) carrying distinct `actor` (the agent) and `subject` (the human or initiating system) claims. For system-initiated workflows, a distinct workload identity may be used instead. | MUST: token exchange with delegation chain preserved for audit. Prior delegation hops should be retained for forensics, but authorization decisions must be based on the token's current actor and subject claims. |
| Credential storage | Local config acceptable. Real credentials discouraged; if production or user credentials are present, reclassify as Level 2. | MUST: OS keychain or secrets manager | MUST: secrets manager with automated rotation policy | MUST: long-lived private keys for signing and identity should be protected by hardware-backed or isolated keystores where available. Ephemeral access tokens must remain short-lived and runtime-confined. |
| Credential lifetime | Real credentials discouraged. If used, treat as Level 2. | SHOULD: bounded lifetime, rotation on schedule | MUST: short-lived tokens (minutes to hours) | MUST: short-lived sender-constrained credentials, typically minutes, bounded by transaction or task risk |

**Threat coverage:** MCP-T1 (Identity/Auth Failures), MCP-T2 (Authorization Errors)
**OWASP MCP mapping:** MCP01 (Token Mismanagement), MCP07 (Insufficient Auth)

### 2. Authorization and Delegation

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Tool-level authorization | Not required | SHOULD: tool allowlists per agent role | MUST: ABAC/PBAC for tool access, supplemented by tool-based access control (TBAC) enforcing parameter-level constraints. TBAC evaluates the specific tool request against verifiable agent identity before execution. | MUST: TBAC with continuous real-time evaluation, anomaly detection, and automated revocation of compromised agent credentials |
| Scope management | No restriction | SHOULD: scoped permissions per server connection | MUST: least-privilege scopes; [incremental scope consent](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) via `WWW-Authenticate` challenges rather than requesting maximal scopes upfront | MUST: structured authorization intent via [Rich Authorization Requests (RFC 9396)](https://datatracker.ietf.org/doc/html/rfc9396) using the `authorization_details` parameter for all sensitive tool operations |
| Delegation depth | Not applicable | SHOULD: defined maximum depth for agent chains | MUST: enforced depth limits with TTL constraints and audience restrictions | MUST: enforced depth limits, audience restrictions, and sender-constrained tokens at every hop |
| Token binding | Not required | Not required | MUST: sender-constrained tokens ([DPoP](https://datatracker.ietf.org/doc/html/rfc9449) or mTLS) for all delegated operations involving sensitive data | MUST: sender-constrained tokens with hardware-attested key material where platform supports it |
| Scope narrowing on delegation | Not applicable | SHOULD: scope narrows at each hop | MUST: scope narrows at each hop, cannot exceed delegating principal's effective permissions | MUST: scope narrows at each hop with cryptographic binding to transaction path |
| Audience restriction | Not required | SHOULD: audience (`aud`) claim validation on received tokens | MUST: [Resource Indicators (RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707) specifying the target MCP server's canonical URI. Authorization server must reject tokens where audience does not match. | MUST: Resource Indicators enforced globally, integrated with dynamic endpoint discovery via [Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/rfc9728/) |
| Token passthrough | Not applicable | MUST: MCP servers must not accept tokens intended for themselves and forward those same tokens to upstream APIs. See [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices#token-passthrough). | MUST: downstream authentication managed exclusively via [token exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693) producing distinct, scoped tokens for each upstream resource | MUST: token exchange with sender-constrained bindings for all downstream calls |
| Human-in-the-loop | Warning on untrusted tools | MUST: explicit user confirmation for all destructive or state-mutating actions. MCP [elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) provides a standardized mechanism for server-initiated user input requests. | MUST: configurable centralized approval policies with step-up authentication for high-impact actions | MUST: multi-party approval workflows for irreversible or high-value operations, with continuous context validation |

**Threat coverage:** MCP-T2 (Authorization Errors), MCP-T9 (Trust Boundary Failures)
**OWASP MCP mapping:** MCP02 (Privilege Escalation), MCP07 (Insufficient Auth)

### 3. Transport and Network Security

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Transport encryption | Not required for stdio. Localhost HTTP acceptable. | MUST: TLS for all remote connections | MUST: TLS 1.3 and mTLS for server-to-server connections, certificate validation enforced | MUST: mTLS governed by workload identity federation (e.g., SPIFFE / SPIRE) and hardware trust anchors |
| Network binding | MUST for HTTP transport: bind exclusively to 127.0.0.1; binding to 0.0.0.0 is prohibited. stdio transport preferred. See [MCP transport security warning](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning). | MUST: explicit internal interface binding mapped to authenticated ingress. No 0.0.0.0. | MUST: network segmentation between MCP components | MUST: dedicated network segments, default-deny egress with explicit allowlists, proxy enforcement, and logging for outbound destinations |
| Origin and CSRF protection | MUST for HTTP transport: validate `Origin` header, validate `Host` header. Not applicable for stdio. | MUST: `Origin` validation, `Host` validation, and CSRF protections for all HTTP endpoints | MUST: strict origin policies with authentication required for all remote access | MUST: strict origin policies, additional request signing, and DNS pinning |
| Payload limits | Optional | MUST: defined payload size limits and basic recursion depth controls | MUST: enforced payload and recursion depth limits with per-session rate limiting | MUST: enforced limits with rate limiting per client/tenant and anomaly-based throttling |
| Message integrity | Not required | SHOULD: payload hashing and strict content-length validation | MUST: application-layer digital signatures (e.g., ECDSA P-256) over the full JSON-RPC message body | MUST: digital signatures with unique nonces and time-window validation to prevent replay |
| Local HTTP exposure | If using HTTP, MUST: validate `Origin`, bind to localhost only. stdio or Unix domain sockets preferred. Unauthenticated local HTTP is non-compliant above Level 1. | N/A (remote connections require authentication) | N/A | N/A |

**Threat coverage:** MCP-T7 (Session/Transport Failures), MCP-T8 (Network Binding Failures), MCP-T10 (Resource Management)
**OWASP MCP mapping:** MCP05 (Command Injection), MCP09 (Shadow Servers)

### 4. Isolation and Sandboxing

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Execution isolation | SHOULD: execute within a restricted local user context. MUST NOT access production credentials or live data. | MUST: application sandboxing or containerized execution with resource limits | MUST: strong container isolation (e.g., gVisor, Kata Containers). No shared runtime across trust boundaries. | MUST: strong tenant isolation with attested workload identity. TEE / confidential containers should be used where threat model, regulation, or platform supports it. |
| Data isolation | Synthetic/mock data only. If production data is accessed, reclassify as Level 2+. | MUST: per-user data separation | MUST: per-tenant data isolation with encryption | MUST: per-tenant encryption with tenant-specific keys |
| Context isolation | Not required | SHOULD: scope cached tool outputs and context to the current user session | MUST: persistent context, memory, and cached tool outputs scoped to user, tenant, task, and agent boundary. Context from one workflow must not be reused in another without explicit policy authorization. | MUST: cross-tenant context sharing prohibited. Shared channels require redaction and release controls. |
| Snapshot and rollback | SHOULD: environment supports snapshot/rewind for experimentation | Optional | SHOULD: rollback capability for MCP server updates | MUST: rollback capability, staged rollouts, canary deployments |

**Threat coverage:** MCP-T5 (Data Protection), MCP-T8 (Network Binding Failures), MCP-T9 (Trust Boundary Failures)
**OWASP MCP mapping:** MCP10 (Context Over-Sharing)

### 5. Logging and Observability

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Action logging | Optional, primarily for debugging | MUST: structured logging capturing tool identity, caller identity, policy decision, resource target, outcome, and correlation identifiers. Raw parameters and tool outputs must be logged only after redaction, hashing, or field-level tokenization. | MUST: comprehensive logging of tool invocations, authorization decisions, and security-relevant failures with full parameter redaction | MUST: immutable, tamper-evident logging of all interactions |
| Delegation chain logging | Not required | SHOULD: correlation IDs linking related events | MUST: full delegation chain reconstruction via correlation IDs, with scope, binding type, and audience at each hop | MUST: full delegation chain reconstruction with policy version, attestation state, and scope at each hop |
| Log schema | Freeform | SHOULD: structured format, mapped to OCSF or CEF | MUST: structured format mapped to OCSF or CEF with agentic extension fields (`delegation_path`, `attestation_state`, `correlation_id`) | MUST: structured format with mandatory agentic fields, correlated in SIEM with model, runtime, and infrastructure telemetry |
| Monitoring and alerting | Not required | SHOULD: centralized log aggregation | MUST: SIEM integration, anomaly detection on agent behavior | MUST: continuous monitoring, automated containment triggers, incident response hooks (kill-switch, tool disablement) |

**Threat coverage:** MCP-T12 (Logging Gaps)
**OWASP MCP mapping:** MCP08 (Lack of Audit and Telemetry)

### 6. Supply Chain and Lifecycle

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Server provenance | Warning when running unverified servers | SHOULD: provenance checks for tool definitions and server packages | MUST: code signing verification before installation, SBOM tracking | MUST: code signing, SBOM, reproducible builds, binary authorization. Execution should be blocked for any server lacking a signed SBOM verified within a defined window. |
| Server inventory | Not required | SHOULD: documented inventory of deployed servers with owner and trust status. The [MCP Registry](https://modelcontextprotocol.io/specification/2025-11-25) provides a discovery mechanism for known servers. | MUST: centralized inventory with metadata (version, owner, purpose, allowed deployment environments) | MUST: centralized inventory with automated discovery of shadow deployments. Production environments must detect and alert on unregistered MCP servers. |
| Update management | No restriction | SHOULD: version tracking | MUST: dependency pinning with hash verification, vulnerability scanning | MUST: dependency pinning, automated scanning, staged rollout, forced upgrades for known CVEs |
| Decommissioning | Not required | SHOULD: documented removal process | MUST: complete removal of deprecated servers, credential revocation | MUST: automated lifecycle policies, downstream delegation revocation on decommission |

**Threat coverage:** MCP-T6 (Integrity/Verification), MCP-T11 (Supply Chain Failures)
**OWASP MCP mapping:** MCP03 (Tool Poisoning), MCP04 (Supply Chain Attacks), MCP09 (Shadow Servers)

### 7. Tool Definition, Input, and Output Integrity

Tool descriptions, parameter schemas, and return values are attack surfaces, not ordinary metadata. The [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) and recent security research demonstrate that tool poisoning, schema corruption, and output-driven prompt injection are among the most effective attack vectors against MCP deployments. This section addresses MCP-T3 (Input Validation Failures) and MCP-T4 (Data/Control Boundary Failures).

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Tool schema integrity | SHOULD: review tool descriptions and parameter schemas before use | SHOULD: pin trusted tool definitions and alert on changes | MUST: cryptographically pin approved tool definitions; changes require review and re-approval | MUST: signed tool-definition manifests with change approval and rollback. Unsigned definitions rejected at runtime. |
| Input validation | SHOULD: validate obvious dangerous inputs | MUST: strict JSON schema validation rejecting undeclared parameters (`additionalProperties: false`). Sanitize file paths against directory traversal. | MUST: enforce strict schemas, deny undeclared fields, validate file paths, URLs, and command parameters. Reject symlinks and prevent path traversal. | MUST: policy-aware validation with per-tool allowlists, deny rules, and deep content inspection for encoded command syntax |
| Output handling | SHOULD: treat tool output as untrusted | MUST: sanitize tool outputs before returning them to the model context when reused downstream | MUST: classify and sanitize tool output to prevent downstream prompt injection, SSRF, and command injection. Strip control characters and apply context-aware encoding. | MUST: content classification and policy enforcement before output may influence another tool, server, or agent |
| SSRF and traversal defense | Not required | MUST: restrict target URL schemes to HTTPS. Sanitize all file paths against directory traversal. | MUST: deny DNS resolution to loopback (127.0.0.0/8), link-local, and cloud metadata endpoints (169.254.169.254) | MUST: all network egress through strict allowlists managed by inspected egress proxies |

**Threat coverage:** MCP-T3 (Input Validation Failures), MCP-T4 (Data/Control Boundary Failures)
**OWASP MCP mapping:** MCP03 (Tool Poisoning), MCP05 (Command Injection), MCP06 (Prompt Injection via Context)

### 8. Session and Discovery Security

| Control | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- |
| Session integrity | Not required | MUST: session identifiers must not be used as authenticators. Verify authorization on every request. Generate unpredictable session IDs bound to the authenticated principal. | MUST: session binding, expiration, and rotation according to risk. Stateful MCP servers must verify authorization per request. | MUST: session integrity with continuous re-evaluation and automated termination on anomaly detection |
| Authorization discovery | Not applicable (local) | SHOULD: support [OAuth Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/rfc9728/) for authorization server discovery | MUST: MCP servers expose Protected Resource Metadata. MCP clients use it for authorization server discovery. Should support incremental scope elevation via `WWW-Authenticate` challenges. | MUST: Protected Resource Metadata with [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0-final.html). Clients must support both discovery mechanisms. |
| Elicitation security | Not required | SHOULD: treat server-provided prompts and [elicitation requests](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) as untrusted. Servers must not use form mode to request credentials. | MUST: elicitation and sampling flows isolated from privileged tool invocation unless policy explicitly allows coupling and logs it | MUST: elicitation-originated content treated as untrusted input requiring full validation before influencing tool parameters or execution |
| Refresh tokens | Not applicable | If issued, must be protected as confidential credentials and should be rotated | MUST: refresh tokens rotated, stored securely, and not treated as substitutes for runtime authorization at the MCP server | MUST: refresh token rotation enforced, with revocation propagated within defined SLA |

**Threat coverage:** MCP-T1 (Identity/Auth Failures), MCP-T7 (Session/Transport Failures)
**OWASP MCP mapping:** MCP01 (Token Mismanagement), MCP07 (Insufficient Auth)

## Threat Coverage Summary

This matrix shows the minimum expected coverage per threat category at each level. [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) categories are cross-referenced where applicable.

| CoSAI Threat Category | OWASP MCP Top 10 | L1 | L2 | L3 | L4 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| MCP-T1: Identity/Auth Failures | MCP01, MCP07 | Partial | MUST | MUST | MUST |
| MCP-T2: Authorization Errors | MCP02, MCP07 | Partial | MUST | MUST | MUST |
| MCP-T3: Input Validation Failures | MCP05 | SHOULD | MUST | MUST | MUST |
| MCP-T4: Data/Control Boundary Failures | MCP03, MCP06 | Partial | SHOULD | MUST | MUST |
| MCP-T5: Data Protection | MCP10 | Partial (mock data) | MUST | MUST | MUST |
| MCP-T6: Integrity/Verification | MCP03, MCP04 | Not required | SHOULD | MUST | MUST |
| MCP-T7: Session/Transport Failures | MCP01 | SHOULD (localhost) | MUST | MUST | MUST |
| MCP-T8: Network Binding Failures | MCP09 | MUST (localhost bind) | MUST | MUST | MUST |
| MCP-T9: Trust Boundary Failures | MCP02 | Partial | MUST | MUST | MUST |
| MCP-T10: Resource Management | -- | Not required | MUST | MUST | MUST |
| MCP-T11: Supply Chain Failures | MCP04 | Not required | SHOULD | MUST | MUST |
| MCP-T12: Logging Gaps | MCP08 | Not required | MUST | MUST | MUST |

## Deployment Pattern Mapping

| Deployment Pattern | Typical Level | Notes |
| :---- | :---- | :---- |
| DP1: All-Local (stdio) | Level 1 or 2 | Level 1 for personal experiments. Level 2 if handling internal data or if multiple users share the environment. |
| DP2: Single-Tenant Remote | Level 2 or 3 | Level 2 for internal tools. Level 3 when serving production workloads or sensitive data. |
| DP3: Multi-Tenant Cloud | Level 3 or 4 | Level 3 for standard SaaS. Level 4 when regulatory obligations apply or tenant isolation failures have material consequences. |

Deployment pattern alone does not determine the level. A local deployment (DP1) processing regulated health data should target Level 3 or higher regardless of its network topology. The level is a function of data sensitivity, blast radius, and regulatory context, not where the server runs.

## Applying Profiles in Practice

Assurance levels define minimum viable security for specific deployment contexts. Organizations should select the appropriate tier based on data sensitivity and threat model, not treat Level 4 as a universal target.

**Token binding is a hard requirement at Level 3.** Without sender-constrained tokens, a compromised agent session can be replayed against downstream services. Teams operating at Level 3 without [DPoP](https://datatracker.ietf.org/doc/html/rfc9449) or mTLS binding are accepting a risk that contradicts the level's stated trust assumptions.

**Level 1 is data isolation, not "no security."** Level 1 does not require runtime process sandboxing (containers, chroot), but it prohibits access to production credentials, live data, and production endpoints. If a Level 1 deployment touches real credentials, it is miscategorized. This is a classification decision, not a configuration knob.

**Level transitions should be planned, not reactive.** A proof-of-concept that succeeds at Level 1 will be pushed toward production. Upgrading from Level 2 to Level 3 requires migrating from standard OAuth tokens to sender-constrained tokens (DPoP), implementing workload identity (e.g., SPIFFE / SPIRE SVIDs), enforcing TBAC on tool execution, and enabling continuous ABAC evaluation.

**OWASP Minimum Bar as a Level 2 prerequisite.** The [OWASP MCP Security Minimum Bar](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/) defines strict deployment gates across five categories (identity, isolation, tooling, validation, deployment). Fulfilling those requirements is the prerequisite for achieving Level 2. Organizations that cannot pass the OWASP baseline should not deploy MCP servers in shared environments.

**Agent gateways for Level 3 and Level 4.** Embedding complex authorization, payload inspection, and identity management logic directly into individual MCP servers creates inconsistent security posture. Deployments targeting Level 3 and above should deploy a centralized proxy or agent gateway as the primary enforcement point for token validation, TBAC policy evaluation, workload identity exchange, and audit logging. Decoupling enforcement from tool execution ensures uniform compliance across heterogeneous server implementations.

**Profiles can be verified.** Each control in the matrix is testable. Future work should define automated checks (similar to SLSA verification tooling and tools like [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)) that validate whether a deployment meets a claimed level. Continuous verification is critical: a server deployed securely on Tuesday may be compromised via an upstream dependency update by Thursday. Level 3 deployments should integrate continuous scanning into deployment pipelines. Level 4 deployments should enforce binary authorization blocking servers without current signed SBOMs.

## Emerging Standards

The agent identity and authorization landscape is evolving rapidly. The following standards and frameworks are informative references for implementers. As these mature, future profile revisions will incorporate them where appropriate.

* [AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) (`draft-klrc-aiagent-auth-01`, Kasselman et al., March 2026): Proposes a comprehensive model using [WIMSE](https://datatracker.ietf.org/wg/wimse/about/) architecture, SPIFFE identifiers, and OAuth extensions. Standardizes agents as workloads within the WIMSE framework. Relevant to the identity controls at Levels 3 and 4.

* [OAuth Identity and Authorization Chaining](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-08) (`draft-ietf-oauth-identity-chaining-08`): Formalizes cross-domain delegation, extending [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange for multi-hop agent chains. Relevant to scope narrowing and delegation depth controls.

* [Transaction Tokens for A2A](https://datatracker.ietf.org/doc/html/draft-liu-oauth-a2a-profile-00) (`draft-liu-oauth-a2a-profile-00`): Provides an alternative to nested `act` claims for preserving call chain context in agent-to-agent communication. May address token size concerns in deep delegation chains.

* [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth-00) (`draft-ietf-oauth-spiffe-client-auth-00`): Profiles SPIFFE SVIDs as OAuth client credentials, enabling agents to authenticate without client secrets. Relevant to Level 3+ credential management.

* [AGNTCY](https://agntcy.org/) (Linux Foundation): Provides reference implementations for Agent Identity Badges and Tool-Based Access Control (TBAC). The TBAC model is referenced in the authorization controls at Level 3+. See [#47](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/47) and [#48](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/48) for evaluation threads.

## Open Questions

1. **Granularity within levels.** Some organizations may need finer distinctions within Level 3 (e.g., "production with PII" vs. "production without PII"). Should sub-levels be supported, or should the matrix stay at four tiers with policy-level refinements handling the edge cases?

2. **SIG alignment.** The agent lifecycle SIG discussion is exploring similar profile concepts for all agent types, not just MCP. This document should stay compatible with that broader direction. If the SIG adopts a different level taxonomy, this matrix should be updatable without structural rework.

3. **Regulatory mapping.** Level 4 currently describes regulatory scope in general terms. A dedicated regulatory compliance annex mapping specific obligations (California AI Transparency Act, EU AI Act, sector-specific requirements) to profile controls may be warranted as a separate deliverable.

4. **Evidence-per-level annex.** A one-page reference showing expected verification artifacts at each level (Protected Resource Metadata endpoint, token audience validation test, tool-definition hash manifest, sandbox config, egress policy, sample audit record, SBOM attestation, decommissioning proof) would make the profiles more actionable for audit teams. Deferred to a follow-up.

5. **MCP extensions and MCP Apps.** The [November 2025 specification](https://modelcontextprotocol.io/specification/2025-11-25) introduced an extensions system for capability negotiation, and [MCP Apps](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/) allow tools to return interactive HTML interfaces. Both introduce new attack surfaces (capability injection, XSS/sandbox escape) that future profile revisions should address.
