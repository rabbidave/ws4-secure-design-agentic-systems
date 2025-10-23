# Zero-Trust MCP - (Draft) Sample Pattern for Validation

## Architecture Overview

```mermaid
graph TD
    subgraph "Interdiction Layer"
        A[Client Extensions<br/>Browser/IDE Plugins<br/>👤 WHO] -->|Local Session| B[Reverse Proxy<br/>Traffic Gateway<br/>📍 WHERE]
        B -->|Session Telemetry| C[Policy Engine<br/>Decision Point<br/>📋 WHAT]
        C -->|Rule Evaluation| D[Validation Framework<br/>Rail Execution<br/>⚙️ HOW]
    end
    
    subgraph "Metadata Requirements"
        E[Regulatory Context<br/>Compliance Rules<br/>❓ WHY]
        F[Data Sensitivity<br/>Classification Level<br/>📋 WHAT]
        G[Contextual State<br/>Retrieved Knowledge<br/>⚙️ HOW]
    end
    
    E --> C
    F --> C
    G --> D

    classDef interdiction fill:#e1f5ff,stroke:#0288d1,stroke-width:2px
    classDef metadata fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    
    class A,B,C,D interdiction
    class E,F,G metadata
```

### Architecture Components

**Interdiction Layer:**
- **Client Extensions**: User-facing agents that capture identity (WHO) and initiate requests
- **Reverse Proxy**: Traffic gateway that intercepts all communications (WHERE)
- **Policy Engine**: Decision point that evaluates access requests against security policies (WHAT)
- **Validation Framework**: Rail execution system that applies input/output filters and content safety checks (HOW)

**Metadata Requirements:**
- **Regulatory Context**: Compliance rules and legal requirements (WHY)
- **Data Sensitivity**: Classification levels for data protection (WHAT)
- **Contextual State**: Runtime knowledge and retrieved context (HOW)

---

### Comparative Vulnerability Matrix

| Attack Vector | Traditional Auth | Zero-Trust MCP | Zero-Trust MCP (Enhanced) |
|--------------|-----------------|----------------|---------------------------|
| **Parameter Tampering** | ✅ Protected (Session binding) | ✅ Protected (Hash binding) | ✅ Protected (Hash + breadcrumb) |
| **Replay Attacks** | ❌ Vulnerable (valid window) | ✅ Protected (atomic consumption) | ✅ Protected (atomic + chain) |
| **Agent Misinterpretation** | ❌ Vulnerable (intent gap) | ✅ Protected (exact params) | ✅ Protected (exact params) |
| **Race Conditions** | ❌ Vulnerable (no state mgmt) | ✅ Protected (Atomic store) | ✅ Protected (Atomic store) |
| **TOCTOU Attacks** | ❌ Vulnerable (auto-generation) | ✅ Protected (real-time validation) | ✅ Protected (real-time validation) |
| **Config Tampering** | ❌ Not addressed | ⚠️ Detection via logs | ✅ Protected (breadcrumb chain) |
| **Chain of Custody** | ❌ Not provided | ⚠️ Audit logs only | ✅ Protected (cryptographic chain) |

### Why Zero-Trust MCP w/ CoC Is Strongest

```typescript
// Complete Protection Stack
{
  // Layer 1: Parameter binding to Authenticating Identity
  params: {resource_id: "RESOURCE_123", amount: 999.00},
  params_hash: sha256(params),
  
  // Layer 2: Atomic consumption of JIT-provisioned Entitlements
  token: {params_hash: "...", jti: "unique-id"},
  atomic_store.consume(token.jti),
  
  // Layer 3: Config integrity (CoC MCP only)
  breadcrumb_hash: "a4f2e9b1...",
  chain_of_custody: [C0, C1, C2, C3],
  
  // Layer 4: Non-repudiation via deploy hash validation
  certificate: {
    signature: "quantum_resistant_sig...",
    chain_valid: true,
    breadcrumb_consistent: true
  }
}
```

**TL;DR**: The breadcrumb chain ensures that even if an attacker compromises the policy engine after authorization, the chain validation will fail
because the configuration hash has changed

**i.e. The policy engine was deployed alongside compute infrastructure and thus has the same constituent hash**
---

# Requirement DLP/DSPM Validation of Tool Parameters



**Remote MCP Services MUST validate incoming parameter strings against the tool's pre-declared data classification** to ensure parameters are appropriate for the tool's sensitivity level and graduated controls.

---

### Reference Implementation Schema (MCP.Handshake.v1.1)

### `transaction` (REQUIRED)
Contains core details about the specific request.

- **`id`** (string, UUID, REQUIRED): A unique identifier for this transaction.
- **`timestamp`** (string, ISO-8601, REQUIRED): Timestamp for when the transaction was initiated.
- **`oauth_session_id`** (string, UUID, REQUIRED): Links this transaction to the OAuth validation session.
- **`request_ip`** (string, OPTIONAL): The IP address from which the client request originated.
- **`user_agent`** (string, OPTIONAL): The client user agent string.

### `identity` (REQUIRED)
Information about the authenticated user, extracted from OAuth provider validation.

- **`sub`** (string, REQUIRED): The user's unique identifier from the OAuth provider.
- **`provider`** (string, REQUIRED): The OAuth provider that validated this identity (matches X-OAuth-Provider header).
- **`email`** (string, OPTIONAL): The user's email address from OAuth claims.
- **`name`** (string, OPTIONAL): The user's display name from OAuth claims.
- **`roles`** (array of strings, OPTIONAL): A list of roles assigned to the user.
- **`validated_at`** (string, ISO-8601, OPTIONAL): Timestamp of when the OAuth token was validated.

### `action` (REQUIRED)
Describes what action is being authorized.

- **`tool`** (string, REQUIRED): The name of the tool being invoked (e.g., `process_transaction`).
- **`parameters_hash`** (string, SHA256, REQUIRED): A cryptographic fingerprint of the tool's specific invocation parameters for integrity checks.
- **`operation`** (string, OPTIONAL): The specific operation within the tool (e.g., `execute`, `validate`).
- **`sensitivity`** (string, enum: `CONFIDENTIAL`, `PUBLIC`, OPTIONAL): The operational sensitivity level of the action.
- **`data_classification`** (object, OPTIONAL): Details about the type of data being accessed.
  - **`value`** (string, REQUIRED if object present): The classification value (e.g., `PII`, `CONFIDENTIAL`).
  - **`reason`** (string, OPTIONAL): A brief explanation for the classification.
  - **`attesting_agent_id`** (string, OPTIONAL): The identifier of the agent that attested to this classification.

### `authorization` (REQUIRED)
The ephemeral token and related authorization details.

- **`ephemeral_token`** (string, JWT, REQUIRED): A single-use, short-lived token binding identity→action.
- **`expires_at`** (string, ISO-8601, REQUIRED): The expiration timestamp of the ephemeral token.
- **`jti`** (string, UUID, REQUIRED): Unique token identifier used for atomic consumption tracking.
- **`issued_at`** (string, ISO-8601, OPTIONAL): When the ephemeral token was issued.
- **`not_before`** (string, ISO-8601, OPTIONAL): Earliest time the token can be used.
- **`scope`** (array of strings, OPTIONAL): Authorized scopes for this action.

### `validation` (OPTIONAL)
Records the results of any policy or security checks performed before approving the request.

- **`status`** (string, enum: `APPROVED`, `DENIED`, REQUIRED if section present): The final validation status.
- **`timestamp`** (string, ISO-8601, REQUIRED if section present): When validation was performed.
- **`checks_performed`** (array of strings, OPTIONAL): List of validation checks executed:
  - `oauth_token_valid`: OAuth token was successfully validated
  - `user_role_check`: User has required roles
  - `parameter_validation`: Parameters match the hash
  - `rate_limit_check`: Request within rate limits
  - `policy_check`: Passes policy engine rules
- **`policy_version`** (string, OPTIONAL): Version of the policy engine used.
- **`tier_level`** (string, OPTIONAL): Security tier determined during validation.
- **`reason`** (string, OPTIONAL): Explanation, typically provided if status is `DENIED`.

### `audit` (OPTIONAL)
Contains information essential for logging and security audits.

- **`client_id`** (string, REQUIRED if section present): Identifier for the client application.
- **`integration_id`** (string, REQUIRED if section present): Identifier for the specific integration.
- **`correlation_id`** (string, OPTIONAL): For distributed tracing across systems.
- **`session_fingerprint`** (string, OPTIONAL): Client session fingerprint for security.

### `receipt` (OPTIONAL)
Provides cryptographic proof of the transaction for non-repudiation.

- **`transaction_proof`** (string, REQUIRED if section present): Cryptographic signature of transaction.
- **`timestamp`** (string, ISO-8601, REQUIRED if section present): When receipt was generated.
- **`algorithm`** (string, OPTIONAL): Signature algorithm used (e.g., `RS256`, `HS256`).

### `error_handling` (REQUIRED - always present)
A dedicated section for reporting errors. This object is **always present** to ensure structural consistency. Fields are `null` when no error, populated when error occurs.

- **`status_code`** (integer or null): HTTP status code (e.g., `400`, `500`), or `null` if no error.
- **`error_type`** (string or null): Specific error type, or `null` if no error:
  - `oauth_validation_error`: OAuth token validation failed
  - `token_expired`: Ephemeral token has expired
  - `token_consumed`: Token already used
  - `parameter_mismatch`: Parameters don't match hash
  - `permission_denied`: User lacks required permissions
  - `rate_limit_exceeded`: Too many requests
- **`message`** (string or null): Descriptive error message, or `null` if no error.
- **`retry_allowed`** (boolean or null): Whether retry is safe, or `null` if no error.

***

```json
{
  "transaction": {
    "id": "tx-550e8400-e29b-41d4-a716-446655440000",     // REQUIRED
    "timestamp": "2024-01-21T10:30:00Z",                 // REQUIRED
    "oauth_session_id": "oauth-550e8400-e29b-41d4",      // REQUIRED
    "request_ip": "192.168.1.100",                       // OPTIONAL
    "user_agent": "MCP-Client/1.0"                       // OPTIONAL
  },
  
  "identity": {                                           // REQUIRED section
    "sub": "user-123",                                    // REQUIRED
    "provider": "enterprise-sso",                         // REQUIRED
    "email": "user@example.com",                          // OPTIONAL
    "name": "John Doe",                                   // OPTIONAL
    "roles": ["admin", "operator"],                       // OPTIONAL
    "validated_at": "2024-01-21T10:29:55Z"               // OPTIONAL
  },
  
  "action": {                                             // REQUIRED section
    "tool": "process_transaction",                        // REQUIRED
    "parameters_hash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",  // REQUIRED
    "operation": "execute",                               // OPTIONAL: Specific operation
    "sensitivity": "CONFIDENTIAL",                        // OPTIONAL: Data sensitivity level
    "data_classification": {                              // OPTIONAL: Data handling info
      "value": "PII",
      "reason": "Contains customer personal data"
    }
  },
  
  "authorization": {                                      // REQUIRED section
    "ephemeral_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",  // REQUIRED
    "expires_at": "2024-01-21T10:30:30Z",                // REQUIRED
    "jti": "550e8400-e29b-41d4-a716-446655440001",       // REQUIRED
    "issued_at": "2024-01-21T10:30:00Z",                 // OPTIONAL
    "not_before": "2024-01-21T10:30:00Z",                // OPTIONAL
    "scope": ["execute", "read"]                          // OPTIONAL
  },
  
  "validation": {                                         // OPTIONAL section
    "status": "APPROVED",                                 // REQUIRED if present
    "timestamp": "2024-01-21T10:30:00Z",                 // REQUIRED if present
    "checks_performed": [                                 // OPTIONAL
      "oauth_token_valid",
      "user_role_check",
      "parameter_validation",
      "rate_limit_check",
      "policy_check"
    ],
    "policy_version": "v2.3.1",                          // OPTIONAL
    "tier_level": "tier-2",                              // OPTIONAL
    "reason": null                                        // OPTIONAL
  },
  
  "audit": {                                              // OPTIONAL section
    "client_id": "app-client-001",                       // REQUIRED if present
    "integration_id": "integration-456",                 // REQUIRED if present
    "correlation_id": "corr-789xyz",                     // OPTIONAL
    "session_fingerprint": "fp-abc123def456"             // OPTIONAL
  },
  
  "receipt": {                                            // OPTIONAL section
    "transaction_proof": "sig-a1b2c3d4e5f6...",          // REQUIRED if present
    "timestamp": "2024-01-21T10:30:01Z",                 // REQUIRED if present
    "algorithm": "RS256"                                  // OPTIONAL
  },
  
  "error_handling": {                                     // REQUIRED - always present
    "status_code": null,                                  // null when no error
    "error_type": null,                                   // null when no error
    "message": null,                                      // null when no error
    "retry_allowed": null                                 // null when no error
  }
}
```

#### API Tool Classification Examples

```typescript
const TOOL_CLASSIFICATIONS = {
  "create_credential": 1, "update_user_auth": 1,     // Class 1 - Highest sensitivity
  "transfer_funds": 2, "process_reversal": 2,        // Class 2 - Financial operations
  "create_document": 3, "process_order": 3,          // Class 3 - Business operations
  "list_records": 4, "get_account_info": 4,          // Class 4 - Read operations
  "get_public_data": 5                               // Class 5 - Public data
};

```

Class 4-5 operations use standard MCP 2.1. Class 1-3 sensitive operations use zero-trust extensions, determined by `TOOL_CLASSIFICATIONS`.

#### Implementation Notes

* Every JSON-RPC message MUST be a new HTTP POST request
* OAuth tokens travel in HTTP headers, not in the JSON-RPC payload
* The ephemeral token is consumed atomically using a distributed store (e.g., Redis, etcd) with the JTI as key
* Parameters can be validated server-side if included in the authorization request
* The oauth_session_id allows correlation between OAuth validation and MCP operations

#### Ephemeral Token Claims

```json
{
  "sub": "user-123",              // REQUIRED: User ID from OAuth
  "iss": "mcp-server",           // REQUIRED: Token issuer
  "aud": "mcp-executor",         // REQUIRED: Token audience
  "exp": 1705838430,             // REQUIRED: Expiry timestamp
  "iat": 1705838400,             // REQUIRED: Issued at timestamp
  "jti": "550e8400-e29b-41d4-a716-446655440001",  // REQUIRED: Unique ID for atomic consume
  
  "mcp": {                       // REQUIRED: MCP-specific claims
    "provider": "enterprise-sso", // REQUIRED: OAuth provider
    "tool": "process_transaction", // REQUIRED: Authorized tool
    "parameters_hash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",  // REQUIRED
    "oauth_session_id": "oauth-550e8400-e29b-41d4"  // REQUIRED: Links to OAuth session
  }
}
```

---

### Token Signing and Verification

The critical security property is the cryptographic binding of three elements:
1. **Identity** (WHO) - The authenticated user from OAuth
2. **Tool** (WHAT) - The specific tool being invoked
3. **Parameters** (WHAT) - The exact parameters via SHA256 hash

This binding ensures that a token authorizing `user-123` to execute `process_transaction` with specific parameters cannot be used to:
- Authorize a different user
- Execute a different tool
- Use different parameters

**The signing algorithm is merely the mechanism to ensure this binding cannot be forged.**

### Ephemeral Token Generation

The Remote MCP Service MUST sign ephemeral tokens using a cryptographically secure method:

```javascript
// Example using HS256 (symmetric)
const ephemeralToken = jwt.sign({
  sub: getUserId(sessionToken),              // User ID from OAuth
  exp: Math.floor(Date.now() / 1000) + 30,  // 30 second TTL
  jti: uuid.v4(),                           // Unique ID for atomic consumption
  iss: "mcp-server",                        // Token issuer
  aud: "mcp-executor",                      // Token audience
  mcp: {
    provider: oauthProvider,                // From X-OAuth-Provider header
    tool: tool,                             // Tool being authorized
    parameters_hash: parameters_hash,        // SHA256 of parameters
    oauth_session_id: getSessionId(sessionToken)
  }
}, JWT_SECRET, { algorithm: 'HS256' });
```

### Algorithm Flexibility

The MCP Handshake architecture is **algorithm-agnostic**. Implementers MAY use any secure signing algorithm appropriate for their security requirements:

```javascript
// Example: Using RS256 (asymmetric)
const ephemeralToken = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

// Example: Using ES256 (elliptic curve)
const ephemeralToken = jwt.sign(payload, ecPrivateKey, { algorithm: 'ES256' });

// Example: Future quantum-resistant algorithm
const ephemeralToken = jwt.sign(payload, quantumKey, { algorithm: 'CRYSTALS-DILITHIUM' });
```

**Supported algorithms include but are not limited to:**
- **Symmetric**: HS256, HS384, HS512
- **Asymmetric**: RS256, RS384, RS512, PS256, PS384, PS512
- **Elliptic Curve**: ES256, ES384, ES512
- **Future/Quantum-Resistant**: Any standardized post-quantum algorithms

The choice of algorithm should be based on:
- Performance requirements
- Key management capabilities
- Regulatory compliance needs
- Future-proofing considerations (e.g., quantum resistance)

### Token Verification

When receiving the ephemeral token, the service MUST:

```javascript
async function validateAndConsumeToken(token, actualParams) {
  try {
    // 1. Verify JWT signature (algorithm-agnostic)
    const claims = jwt.verify(token, JWT_SECRET_OR_PUBLIC_KEY);
    
    // 2. Check expiration
    if (claims.exp < Date.now() / 1000) {
      throw new Error("Token expired");
    }
    
    // 3. Validate parameter hash matches (THE CRITICAL BINDING)
    const actualHash = sha256(JSON.stringify(actualParams));
    if (actualHash !== claims.mcp.parameters_hash) {
      throw new Error("Parameter tampering detected");
    }
    
    // 4. Atomically consume the token (example using distributed store)
    const consumed = await atomicStore.compareAndSet(
      `token:${claims.jti}`,
      null,
      'consumed',
      { ttl: 60 }
    );
    
    if (!consumed) {
      throw new Error("Token already used");
    }
    
    return claims;
  } catch (error) {
    throw new Error(`Token validation failed: ${error.message}`);
  }
}
```

### Atomic Consumption Implementation Options

The atomic consumption mechanism can be implemented using various distributed stores:

```javascript
// Option 1: Redis with Lua script
const CONSUME_TOKEN_SCRIPT = `
  if redis.call("exists", KEYS[1]) == 0 then
    redis.call("set", KEYS[1], "consumed", "EX", 60)
    return 1
  else
    return 0
  end
`;

// Option 2: etcd with compare-and-swap
const consumed = await etcdClient.if(
  'token:' + jti, 'Version', '==', 0
).then(
  etcdClient.put('token:' + jti, 'consumed').ttl(60)
);

// Option 3: DynamoDB with conditional write
const params = {
  TableName: 'Tokens',
  Item: { jti: jti, status: 'consumed' },
  ConditionExpression: 'attribute_not_exists(jti)'
};
```

### Security Considerations

1. **Key Management**: Regardless of algorithm choice, signing keys MUST be:
   - Stored securely (e.g., HSM, secure key management service)
   - Rotated periodically
   - Never exposed in logs or error messages

2. **Algorithm Migration**: Systems SHOULD be designed to support algorithm migration:
   ```javascript
   // Support multiple algorithms during transition
   const algorithms = ['HS256', 'RS256', 'ES256'];
   const claims = jwt.verify(token, keyResolver, { algorithms });
   ```

3. **Quantum Readiness**: While current algorithms are sufficient, implementers SHOULD:
   - Design systems to support algorithm updates
   - Monitor NIST post-quantum cryptography standardization
   - Plan for migration when quantum-resistant algorithms mature

### Implementation Notes

- The `jti` (JWT ID) MUST be globally unique to enable atomic consumption
- The `parameters_hash` MUST use a consistent serialization method
- Token TTL (30 seconds) is a balance between security and usability
- The atomic consumption mechanism is algorithm-independent and can use any distributed store that supports atomic operations
