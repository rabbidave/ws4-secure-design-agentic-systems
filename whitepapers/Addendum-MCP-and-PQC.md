---
title: Addendum: Quantum-Resistant AI Infrastructure
author: "Workstream 4: Secure Design Patterns for Agentic Systems"
status: Draft
date: 11 June 2026
---

# White Paper: Quantum-Resistant AI Infrastructure

## Implementing Post-Quantum Cryptography (PQC) in Model Context Protocol (MCP) Architectures

# Executive Summary

As the Model Context Protocol (MCP) becomes the standard for connecting LLMs to enterprise data, it introduces new cryptographic risks. The advent of functionally relevant quantum computing threatens the asymmetric encryption (RSA, ECC) currently securing these data pipes. This paper outlines the design and implementation of a **Quantum-Resistant MCP Server**, addressing both "Harvest Now, Decrypt Later" (HNDL) attacks against long-lived data and the parallel need to migrate signature schemes before quantum forgery becomes practical — signature migration takes longer than key-exchange migration and should not be treated as a lower priority.

This addendum scopes its recommendations to the primitives actually exposed to quantum attack: asymmetric key exchange (RSA, ECC, Diffie-Hellman) and asymmetric signatures (RSA, ECDSA), both broken in polynomial time by Shor's algorithm because they rely on factorization or discrete-log hardness. One-way hashes (SHA-256) and symmetric ciphers (AES) are addressed separately — see "Why This Applies Unevenly" below — because they face only Grover's algorithm, a quadratic (not exponential) speedup, and do not require migration to a different mathematical construction.

# Information Classification & The "Ten-Year Rule"

To prioritize cryptographic agility, organizations must classify data based on its **Value Longevity**.

## Data Classification Definitions

* **Ephemeral Data (\<1 Year):** Session tokens, transient climate data, or stock tickers.
* **Standard Business Data (1–10 Years):** Contractual details, internal strategy, or project roadmaps.
* **Long-Lived Data (10+ Years):** Data that remains sensitive or identifying for decades. If intercepted today, it remains a liability in the quantum era.

All data, regardless of tier, should default to encryption where technically feasible; the tiers below govern *cryptographic agility prioritization* (which systems get hybrid PQC first), not whether encryption is applied at all.

## "Long-Lived" Data Types

Specific focus is required for data that cannot be changed if compromised:

* **Biometric Markers:** DNA sequences, high-resolution fingerprints, and retinal scans.
* **Identity Roots:** Social Security numbers, birth records, and heritage data.
* **National Security:** Cryptographic root keys and long-term classified intelligence.

# Background: The Quantum Threat to MCP

MCP servers typically communicate via **SSE (Server-Sent Events)** over HTTPS or **STDIO** for local processes. While HTTPS (TLS 1.2/1.3) is currently secure, the key exchange mechanism (Diffie-Hellman or Elliptic Curve) is vulnerable to Shor's Algorithm. An adversary capturing MCP traffic today can store it and decrypt it once a quantum computer is available, compromising the long-lived data fed to the AI.

## Why This Applies Unevenly: Shor vs. Grover

Not every cryptographic primitive in an MCP deployment is equally exposed, and the roadmap below is scoped accordingly.

**Broken outright (Shor's algorithm):** RSA, Diffie-Hellman, ECC/ECDH, and ECDSA rely on factorization or discrete-log hardness. Both problems have exploitable periodic structure that a quantum Fourier transform solves in polynomial time. These *must* migrate to lattice-based replacements — ML-KEM for key exchange, ML-DSA for signatures — because there is no smaller parameter fix; the underlying hardness assumption is gone.

**Weakened, not broken (Grover's algorithm):** One-way hashes (SHA-256, SHA-384) and symmetric ciphers (AES) have no algebraic structure for Shor's algorithm to exploit. Grover's algorithm gives only a quadratic speedup on brute-force search, so a 256-bit hash or a 256-bit key retains ~128-bit security against a quantum adversary — still computationally infeasible. The fix here, if any, is a longer output/key length, not a different mathematical construction.

This distinction matters beyond theory: it determines what actually needs to change in an MCP deployment's payload design, not just its transport layer. See "Per-Class Axiom Validation" below.

## Current Design Status

As of 2026, the USA Federal Government and industry are transitioning to **NIST FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)**. Hybrid key exchanges—which combine a classical key with a quantum-resistant one—are the current "Gold Standard" for MCP implementation; if the PQC algorithm is later found to have a flaw, classical encryption may provide temporary security. The National Security Agency (NSA) has established a phased timeline for National Security Systems (NSS) to transition to Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).

* **January 1, 2027 — Procurement Inflection Point:** Any NSS system acquired or deployed after this date must support CNSA 2.0 algorithms (ML-KEM and ML-DSA). This impacts current RFP and planning cycles, as systems designed today will likely be delivered after this cutoff.
* **January 2, 2030:** TLS 1.3 (or successor) mandated across all federal systems (EO 14144).
* **December 31, 2030:** Deadline for phasing out systems unable to support CNSA 2.0 (legacy systems).
* **December 31, 2033 — Final System Deadline:** All custom applications and legacy infrastructure are expected to reach exclusive use of CNSA 2.0 standards.
* **2035 — Full Quantum Resistance:** The ultimate deadline set by National Security Memorandum 10 (NSM-10) for complete migration across all federal national security systems.

**Commercial & Commercial Cloud (AWS, Azure, GCP) Milestones:**

* **2025–2026:** Hybrid PQC is currently being deployed by major CSPs (e.g., AWS KMS) and web browsers for PQC support in web services.
* **2029:** Targeted date by major tech firms like [Google](https://blog.google/innovation-and-ai/technology/safety-security/cryptography-migration-timeline/) and [Cloudflare](https://blog.cloudflare.com/post-quantum-roadmap/) for full, non-hybrid post-quantum security implementation.

**Critical Infrastructure:** Expected to comply with PQC regulations by 2026–2028. Hybrid implementations are a transitional step in 2025–2026 but do not satisfy long-term (2030+) requirements.

# Design Architecture: The PQC-MCP Server

The proposed design utilizes a **Hybrid KEM (Key Encapsulation Mechanism)** approach.

## Core Components

* **Transport:** TLS 1.3 with Hybrid Key Exchange (X25519 + ML-KEM-768).
* **Authentication:** Digital signatures using ML-DSA.
* **Payload:** Standard JSON-RPC 2.0. For Class 1–2 data (see Per-Class Axiom Validation below), payload fields referencing sensitive values MUST carry a one-way hash or server-resolved reference token, never the raw value. This constrains HNDL blast radius independent of transport KEM status — hybrid PQC on the wire does not help if the raw secret is what's inside the envelope.

## Per-Class Axiom Validation: Abstraction as a Control, Not Just Transport

HNDL exposure is a property of what is transmitted, not only of the key exchange securing the channel. Hybrid PQC TLS protects the session; it does not protect a design that puts the actual secret — a raw key, a bearer token, an unhashed identifier — inside the JSON-RPC payload itself. An adversary who later factors today's session recovers exactly what was sent. If what was sent is a one-way hash or opaque reference (resolved server-side against a securely-held value), factoring the session yields nothing usable.

This means Long-Lived Data requires a payload-level control in addition to transport-level PQC:

| Data Class | Longevity | Transport Requirement | Payload Requirement |
|---|---|---|---|
| Class 1 (PII: SSN, credentials) | 10+ yrs | Hybrid PQC KEM (X25519+ML-KEM-768) | MUST NOT transit as raw value — one-way hash or server-resolved reference only |
| Class 2 (Sensitive: txn history, biometric) | 10+ yrs | Hybrid PQC KEM | MUST NOT transit as raw value — one-way hash or server-resolved reference only |
| Class 3 (Confidential: invoices, profiles) | 1–10 yrs | TLS 1.3 (hybrid optional) | SHOULD use reference where feasible |
| Class 4 (Internal) | 1–10 yrs | Standard TLS 1.3 | No restriction |
| Class 5 (Public) | <1 yr | Standard TLS 1.3 | No restriction |

**Why this matters independent of KEM migration status:** an implementation can be fully hybrid-PQC at the transport layer and still be HNDL-exposed if a tool is invoked with the actual SSN or key material sitting in a payload field, rather than a hash-bound reference resolved against a vault server-side. This is the same abstraction pattern as Axiom 1 in the Zero-Trust Tool Invocation Standard (`H(approved_params) == H(executed_params)`) — this addendum requires it explicitly for Class 1–2 data rather than treating it as optional hardening layered on top of transport PQC.

# Build & Implementation (Code-Level)

This implementation uses **Python** and the **OQS (Open Quantum Safe)** library to wrap a standard MCP server.

## Environment Setup

```bash
pip install mcp liboqs-python
```

## Implementing a PQC-Enabled MCP Server

The following example demonstrates an MCP server that handles "Long-Lived" biometric data (fingerprint templates) using a quantum-safe wrapper. Note the `record_ref` parameter: it is validated as an opaque reference, never a raw identifier, so that capturing this call today and decrypting it after a future factorization does not yield the underlying SSN, fingerprint hash, or key material directly.

```python
from mcp.server import Server
import oqs  # Open Quantum Safe library
import json

# Initialize MCP Server
app = Server("PQC-Secure-Biometric-Vault")

# 1. Setup Quantum-Safe Key Encapsulation (ML-KEM-768)
kem_name = "ML-KEM-768"

def is_opaque_reference(value: str) -> bool:
    """
    Confirms record_ref is a one-way hash or server-issued reference token,
    not a raw identifier. Replace with your organization's reference format
    validation (e.g., a fixed-length hex digest or vault-issued UUID).
    """
    return len(value) in (64, 96, 128) and all(c in "0123456789abcdef" for c in value.lower())

@app.tool()
async def store_long_lived_data(data_type: str, record_ref: str, encrypted_payload: str):
    """
    Handles storage of data types lasting >10 years.
    Expects payload already wrapped in a PQC envelope.

    record_ref MUST be a one-way hash or opaque server-issued reference —
    never the raw identifier (SSN, biometric value) itself. Passing the raw
    value here defeats the transport-layer PQC protection above: HNDL
    capture of this call recovers the identifier directly once decrypted,
    regardless of KEM strength.
    """
    if data_type not in ["dna", "fingerprint", "ssn"]:
        return {"status": "rejected", "reason": "Insufficient classification"}
    if not is_opaque_reference(record_ref):
        return {"status": "rejected", "reason": "raw identifier in payload"}
    # Logic to store in a Post-Quantum hardened database
    return {"status": "success", "security": "ML-KEM-768 protected"}

@app.resource("vault://biometrics/{record_ref}")
async def get_biometric(record_ref: str):
    # ML-DSA Signature verification logic here
    if not is_opaque_reference(record_ref):
        raise ValueError("raw identifier not permitted in resource URI")
    return "Fingerprint_Template_PQC_Encrypted_Blob"

if __name__ == "__main__":
    app.run_stdio()
```

## Client-Side Hybrid Handshake (Conceptual)

To truly secure the transport, the client must initiate a hybrid handshake. Using a PQC-compatible library like BoringSSL:

```c
// Setting TLS groups to include ML-KEM
SSL_CTX_set1_groups_list(ctx, "X25519Kyber768Draft00:X25519");
```

# Implementation Roadmap

1. **Inventory:** Identify all MCP resources handling DNA, fingerprints, or identity data.

2. **Agility Layer:** Deploy an MCP Proxy that supports TLS 1.3 Hybrid modes. All HTTPS should use hybrid post-quantum TLS **X25519MLKEM768** — the hybrid key exchange that combines classical X25519 with NIST FIPS 203 ML-KEM-768. The handshake is protected as long as either component holds, so the system survives either a quantum attacker or a flaw in the new PQ algorithm. For low-power devices or simple workloads, NIST has also designed and is testing other PQC algorithms that might be useful for MCP applications:
   * **HQC (Hamming Quasi-Cyclic):** Selected by NIST in March 2025 as a 5th algorithm, HQC is a backup to ML-KEM. It is code-based and considered for its robustness and potential efficiency in specific hardware implementations.
   * **Ascon (Lightweight Cryptography Standard):** Released in 2025 (NIST SP 800-232), Ascon is specifically for lightweight cryptography (LWC) in constrained devices. While technically symmetric lightweight crypto rather than post-quantum asymmetric crypto, it is the primary NIST standard for IoT security.

   Note that MCP server capacity will need to be tested, as PQC algorithms require greater CPU cycles for encryption/decryption than RSA.

3. **Signature Migration:** Transition from RSA/ECDSA to ML-DSA for server identity. Note that many third parties carry their own classical TLS configurations; vendor PQ rollout is the only path forward for these. Track their respective release notes.

4. **Audit:** Ensure "Long-Lived Data" is encrypted at rest using AES-256 for CNSA 2.0 compliance. (AES-128 and AES-256 are both quantum-resistant under Grover's algorithm; AES-256 is specified here for compliance margin, not because AES-128 is broken.)

5. **Payload Abstraction Audit:** For every Class 1–2 tool identified in Step 1, verify no raw long-lived identifier (SSN, biometric value, key material) is ever passed in a JSON-RPC parameter — only one-way hashes or server-resolved references, per the Zero-Trust Tool Invocation Standard's Axiom 1. This step is independent of, and should precede, completion of Steps 2–3: it bounds HNDL exposure today, without waiting on KEM or signature library support.

# Conclusion

The Model Context Protocol is the gateway to enterprise intelligence. By classifying information based on its lifespan and implementing **ML-KEM** and **ML-DSA**, organizations can ensure that today's AI interactions do not become tomorrow's data breaches. Transport-layer PQC alone is insufficient, however, if long-lived secrets are still transmitted as raw values in the payload — abstraction via one-way hash or server-resolved reference (Step 5) closes that gap immediately and does not depend on vendor PQC rollout timelines. For data lasting over 10 years, both controls — hybrid key exchange and payload abstraction — are functional requirements, not optional hardening.
