%%%
title = "Cryptographically Verifiable Actor Chain for OAuth 2.0 Token Exchange"
abbrev = "SPICE-ACTOR-CHAIN"
category = "info"
docName = "draft-mw-spice-actor-chain-00"
ipr = "trust200902"
area = "Security"
workgroup = "SPICE"
keyword = ["actor chain", "spice", "rfc8693", "token exchange", "workload identity", "delegation", "AI agents"]
date = 2026-03-10

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-spice-actor-chain-00"
stream = "IETF"
status = "informational"

[[author]]
initials = "A."
surname = "Prasad"
fullname = "A Prasad"
organization = "Oracle"
  [author.address]
  email = "a.prasad@oracle.com"

[[author]]
initials = "R."
surname = "Krishnan"
fullname = "Ram Krishnan"
organization = "JPMorgan Chase & Co"
  [author.address]
  email = "ramkri123@gmail.com"

[[author]]
initials = "D."
surname = "Lopez"
fullname = "Diego R. Lopez"
organization = "Telefonica"
  [author.address]
  email = "diego.r.lopez@telefonica.com"

[[author]]
initials = "S."
surname = "Addepalli"
fullname = "Srinivasa Addepalli"
organization = "Aryaka"
  [author.address]
  email = "srinivasa.addepalli@aryaka.com"

%%%

.# Abstract

This document defines an extension to OAuth 2.0 Token Exchange {{!RFC8693}} that addresses the problem of **Delegation Auditability Gaps** in multi-hop service environments. Current standards treat prior actors in a delegation chain as "informational only," providing no cryptographic proof of the actual delegation path. This document proposes a new `actor_chain` claim — a **Cryptographically Verifiable Actor Chain** — that replaces the informational-only nested `act` claim with a tamper-evident, ordered record of all actors. This solution enables high-assurance data-plane policy enforcement and forensic auditability, particularly for dynamic AI agent-to-agent workloads where susceptibility to **prompt injection attacks** can lead to unauthorized delegation paths.

{mainmatter}

# Introduction

This document defines an extension to OAuth 2.0 Token Exchange {{!RFC8693}} to support high-assurance identity delegation through cryptographically verifiable actor chains. 

In modern multi-service and AI-agent environments, a workload often delegates its authority to another agent, which may in turn delegate to others. While {{!RFC8693}} provides the `act` (actor) claim to represent delegation, it explicitly restricts prior actors in a nested chain to be "informational only," excluding them from access control considerations. This creates a significant **Delegation Auditability Gap**: Relying Parties cannot verify the full path of authority, and attackers can potentially hide lateral movement or **prompt injection-induced hijacking** within unverified informational claims.

By providing a standardized **Cryptographically Verifiable Actor Chain**, this extension replaces the informal nested `act` structure with a policy-enforceable, ordered, and tamper-evident record of all participants. This establishes a **delegation** axis of accountability, ensuring that any service in a global delegation chain can be verified for identity, integrity, and (optionally) physical residency.

This solution addresses several critical gaps in {{!RFC8693}}:

1. **Cryptographic Audit Trail**: Proves that each prior actor actually participated in the delegation chain and that the sequence has not been tampered with.
2. **Data-Plane Policy Enforcement**: Enables Relying Parties to write fine-grained authorization policies based on any actor in the path (e.g., "originating actor must be X").
3. **Dynamic AI Agent Topologies**: Provides a scalable architecture for the unpredictable and deep delegation chains common in autonomous agent networks.
4. **Data-Plane Efficiency**: Uses a flat, ordered array structure optimized for high-throughput parsing and indexing in cloud-native proxies (e.g., Envoy).

This specification is part of a three-axis "Truth Stack" for AI agent governance:

| Specification | Axis | Question Answered | STRIDE Coverage |
| :--- | :--- | :--- | :--- |
| **Actor Chain** (this document) | Identity | WHO delegated to whom? | Spoofing, Repudiation, Elevation of Privilege |
| **Intent Chain** ({{!I-D.draft-mw-spice-intent-chain}}) | Content | WHAT was produced and transformed? | Repudiation, Tampering |
| **Inference Chain** ({{!I-D.draft-mw-spice-inference-chain}}) | Computation | HOW was the output computed? | Spoofing (computational), Tampering (model) |

| Chain | Plane | Token Content | Full Chain | Primary Consumer |
| :--- | :--- | :--- | :--- | :--- |
| **Actor** | Data Plane | Full chain inline | In token | Every Relying Party (real-time authorization) |
| **Intent** | Audit Plane | merkle root only | External registry | Audit systems, forensic investigators |
| **Inference** | Audit Plane | merkle root only | External registry | Auditors, compliance systems |

This extension is designed to be backward-compatible and format-agnostic, supporting both JSON/JWS (JWT {{!RFC7519}}) and CBOR/COSE (CWT {{!RFC8392}}) representations.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

This document leverages the terminology defined in OAuth 2.0 Token Exchange {{!RFC8693}}, the SPICE Architecture {{!I-D.ietf-spice-arch}}, and the RATS Architecture {{!RFC9334}}.

Actor Chain:
: A Cryptographically Verifiable Actor Chain — an ordered sequence of Actor Chain Entries representing the complete delegation path from the originating actor to the current actor. The token carries identity entries inline and a merkle root (`actor_chain_root`) binding those entries to per-actor cryptographic signatures stored in an external registry.

Actor Chain Entry:
: A JSON object or CBOR map identifying a single actor in the delegation chain, including its identity claims (`sub`, `iss`, `iat`) and an optional Proof of Residency (`por`). The token carries these entries inline for data-plane policy enforcement.

Actor Chain Root:
: The merkle root hash of the complete set of per-actor signatures (`chain_sig` values) in the actor chain, included in the OAuth token as the `actor_chain_root` claim. This binds the data-plane token to the audit-plane evidence.

Actor Chain Registry:
: A service endpoint that stores per-actor signature evidence (`chain_sig` for each entry) in an ordered, append-only log. Discovered via the Authorization Server's metadata (`governance_registry_endpoint`) and queried using the token's `sid` claim. Implementations MAY use a SCITT transparency log {{!I-D.ietf-scitt-architecture}} or equivalent ordered log.

Chain Depth:
: The total number of Actor Chain Entries in an actor chain. Used by policy engines to enforce maximum delegation depth.

Proof of Residency (PoR):
: A cryptographic proof (as defined in {{!I-D.draft-mw-spice-transitive-attestation}}) binding a workload to a specific, verified local environment. When present in an Actor Chain Entry, it provides hardware-rooted assurance of the actor's execution context.

# The Problem: RFC 8693 Actor Limitations

## Single-Actor Semantics

{{!RFC8693}} Section 4.1 defines the `act` claim as a JSON object identifying **the** current actor. While nesting is permitted to represent prior actors, the specification explicitly limits their utility. Only the outermost `act` claim—representing the current actor—is relevant for access control. All prior actors exist solely for informational purposes.

This design was appropriate for traditional web service delegation where chains are short (typically one or two hops) and the identity of the immediate caller is sufficient for authorization. It is insufficient for the emerging class of workloads described below.

## AI Agent Delegation Chains

Modern AI systems increasingly operate as networks of specialized agents. A typical interaction may involve:

```
User -> Orchestrator Agent -> Planning Agent -> Tool Agent -> Data API
```

At each hop, the agent performs a token exchange ({{!RFC8693}}) to obtain credentials appropriate for calling the next service. Under current {{!RFC8693}} semantics, by the time the request reaches the Data API, only the Tool Agent is identified as the actor. The Orchestrator Agent and Planning Agent—which may have been manipulated via **prompt injection** into delegating authority they should not have—are invisible to policy enforcement.

This creates several concrete risks:

- **Lateral Movement**: A compromised agent deep in the chain can impersonate the authority of the originating actor without any cryptographic evidence of the actual delegation path.
- **Policy Bypass**: Fine-grained policies like "only allow data access when the orchestrator is a known, trusted entity" cannot be expressed because the orchestrator's identity is not available for policy evaluation at the data plane.
- **Audit Gaps**: Post-incident forensic analysis cannot reliably reconstruct the delegation path because the nested `act` claims are self-reported and unsigned.

## Structural Limitations of Nested `act`

Beyond the semantic restriction, the nested object structure of `act` in {{!RFC8693}} has practical limitations:

1. **Parsing Complexity**: Each prior actor requires traversing one additional level of JSON nesting. In high-throughput data-plane proxies (e.g., Envoy, Istio sidecars), deep nesting imposes parsing overhead.
2. **Indexing**: It is not possible to efficiently query "the actor at position N" without recursively unwinding the nested structure.
3. **Size Predictability**: The depth of nesting is unbounded, making it difficult to predict token sizes and allocate parsing buffers.
4. **No Integrity**: Each nested `act` is a plain JSON object with no signature or hash binding. Any intermediary could insert, remove, or reorder prior actors without detection.

# The Solution: The Cryptographically Verifiable `actor_chain` Claim

## Overview

This document defines a new claim, `actor_chain`, that provides a Cryptographically Verifiable Actor Chain. When used in a JWT, its value is a JSON array of Actor Chain Entries. When used in a CWT, its value is a CBOR array of Actor Chain Entries. The array is ordered chronologically: index 0 represents the originating actor, and the last index represents the current actor.

The Authorization Server (AS) validates each actor at token exchange time and constructs the `actor_chain`. Each actor cryptographically signs its own identity claims, producing a per-entry `chain_sig`. The full signed entries are stored in an external registry (the Actor Chain Registry), while the token carries only the identity entries and a merkle root (`actor_chain_root`) binding them to the signed evidence. The AS constructs an ordered merkle tree from the `chain_sig` values, ensuring that the ordering of entries is cryptographically enforced. The AS's signature over the entire token (JWS or COSE) provides data-plane integrity.

This architecture separates data-plane concerns (fast access control using identity entries) from audit-plane concerns (per-actor non-repudiation using stored signatures), following the same pattern as the companion Intent Chain {{!I-D.draft-mw-spice-intent-chain}} and Inference Chain {{!I-D.draft-mw-spice-inference-chain}} specifications:

| Chain | Question | Token (data plane) | Registry (audit plane) |
| :--- | :--- | :--- | :--- |
| **Actor Chain** (this document) | WHO participated? | Identity entries + merkle root | Per-actor `chain_sig` |
| **Intent Chain** {{!I-D.draft-mw-spice-intent-chain}} | WHAT was produced? | Content refs + merkle root | Per-entry `intent_sig` |
| **Inference Chain** {{!I-D.draft-mw-spice-inference-chain}} | HOW was it computed? | Model refs + merkle root | Per-entry `inference_sig` |

By requiring per-actor signatures in all three chains and storing them in registries with merkle roots in tokens, a Relying Party obtains O(1) data-plane verification while retaining full per-actor non-repudiation for audit.

## Claim Definition

### Token Claims (Data Plane)

The following claims are included in the OAuth token:

actor_chain:
: REQUIRED. A JSON array of Actor Chain Entry objects. Each element is a JSON object with the following members.

actor_chain_root:
: RECOMMENDED. A string containing the merkle root hash (SHA-256, Base64url-encoded) of the complete set of per-actor chain signatures. This binds the inline identity entries to the signed evidence stored in the Actor Chain Registry. Single-AS deployments that do not require audit-plane non-repudiation MAY omit this claim; in that case, the AS's JWT signature provides data-plane integrity for the `actor_chain` entries. Deployments involving multi-AS federation (where the delegation chain spans more than one Authorization Server) MUST include this claim, because no single AS can vouch for the entire chain and per-actor non-repudiation is required to verify cross-domain hops. Deployments requiring governance alignment with the Intent Chain {{!I-D.draft-mw-spice-intent-chain}} and Inference Chain {{!I-D.draft-mw-spice-inference-chain}} specifications MUST include this claim.

sid:
: RECOMMENDED. A string identifying the session to which this token belongs, as defined in OpenID Connect Back-Channel Logout 1.0 {{!OIDC.BackChannel}}. This specification reuses the registered `sid` claim to partition the Actor Chain Registry, Intent Registry ({{!I-D.draft-mw-spice-intent-chain}}), and Inference Registry ({{!I-D.draft-mw-spice-inference-chain}}) by session. MUST be present whenever `actor_chain_root` is present. When deployed alongside the Intent Chain, the `sid` value MUST equal the `session.session_id` value defined in {{!I-D.draft-mw-spice-intent-chain}}. The same `sid` is carried forward during each token exchange, ensuring all registry entries for a given interaction can be retrieved as a unit. The Actor Chain Registry endpoint is discovered via the Authorization Server's metadata (see (#registry-discovery)), not carried in the token.


### Actor Chain Entry Members

sub:
: REQUIRED (or selectively disclosed). A string identifying the actor, as defined in {{!RFC7519}} Section 4.1.2.

iss:
: REQUIRED (or selectively disclosed). A string identifying the issuer of the actor's identity, as defined in {{!RFC7519}} Section 4.1.1.

iat:
: REQUIRED (or selectively disclosed). The time at which this actor was appended to the chain, represented as a NumericDate as defined in {{!RFC7519}} Section 4.1.6.

por:
: OPTIONAL. A JSON object containing a Proof of Residency binding this actor to a verified execution environment. The structure of this object is defined in {{!I-D.draft-mw-spice-transitive-attestation}}.

### Registry Entry Members (Audit Plane)

The following fields are stored per-entry in the Actor Chain Registry and are NOT included in the token:

chain_sig:
: REQUIRED. A compact JWS {{!RFC7515}} or COSE_Sign1 {{!RFC9052}} signature produced by this actor's private key over the canonical serialization of its own identity claims (`sub`, `iss`, `iat`, and `por` if present). The JWS header MUST include the `jwk` or `kid` member to identify the signing key. The signature proves this specific actor participated in the delegation chain. Ordering of entries is enforced by the merkle tree structure (see (#chain-integrity)), not by cumulative hashing.



## Example Token (Data Plane)

The token carries identity entries inline for policy enforcement and a merkle root binding them to per-actor signatures stored in the registry. No per-actor signatures appear in the token itself.

```json
{
  "aud": "https://data-api.example.com",
  "iss": "https://auth.example.com",
  "exp": 1700000100,
  "nbf": 1700000000,
  "sub": "user@example.com",
  "sid": "session-123",
  "actor_chain_root": "sha256:9f86d08...",
  "actor_chain": [
    {
      "sub": "https://orchestrator.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000010,
      "por": {
        "wia_kid": "spiffe://example.com/wia/node-1",
        "env_hash": "sha256:abc123..."
      }
    },
    {
      "sub": "https://planner.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000030
    },
    {
      "sub": "https://tool-agent.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000050,
      "por": {
        "wia_kid": "spiffe://example.com/wia/node-3",
        "env_hash": "sha256:ghi789..."
      }
    }
  ]
}
```

## Example Registry Entries (Audit Plane)

The Actor Chain Registry stores the full per-actor signature evidence:

```json
{
  "session_id": "session-123",
  "actor_chain_root": "sha256:9f86d08...",
  "entries": [
    {
      "sub": "https://orchestrator.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000010,
      "chain_sig": "eyJhbGciOiJFUzI1NiIsImt..."
    },
    {
      "sub": "https://planner.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000030,
      "chain_sig": "eyJhbGciOiJFUzI1NiIsImt..."
    },
    {
      "sub": "https://tool-agent.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000050,
      "chain_sig": "eyJhbGciOiJFUzI1NiIsImt..."
    }
  ]
}
```

The merkle tree is constructed from the `chain_sig` values as ordered leaf nodes (index 0 is the leftmost leaf). The ordering of entries is cryptographically enforced by the merkle tree structure — reordering entries changes the leaf positions, which changes the merkle root. The resulting root hash is included in the token as `actor_chain_root`. An auditor can reconstruct the merkle tree from the registry entries and verify it matches the root in the token.

## Token Exchange Flow

When an actor (Service B) receives a token containing an `actor_chain` and needs to call a downstream service (Service C), the following token exchange flow occurs:

1. **Service B** signs the canonical serialization of its own identity claims (`sub`, `iss`, `iat`) with its private key, producing `chain_sig`.
2. **Service B** sends a token exchange request to the Authorization Server (AS) per {{!RFC8693}} Section 2.1.
3. The `subject_token` contains the existing `actor_chain`.
4. The `actor_token` identifies Service B and includes its `chain_sig`.
5. The AS validates the existing `actor_chain`:
    - Verifies the JWT signature on the `subject_token`.
    - Validates actor identities through its own policy (e.g., client registration, mTLS certificate).
    - Enforces any `max_chain_depth` policy.
6. The AS validates Service B's `chain_sig` against Service B's public key.
7. The AS stores Service B's entry (identity claims + `chain_sig`) in the Actor Chain Registry.
8. The AS appends Service B's `chain_sig` as a new leaf and recomputes the merkle root over all `chain_sig` values (existing + Service B's).
9. The AS constructs a new token with:
    - The extended `actor_chain` array (identity entries only: `sub`, `iss`, `iat`, optional `por`).
    - The updated `actor_chain_root` (new merkle root).
    - The `sid` identifying the session.
10. The AS signs the entire JWT and issues the token.

## Data-Plane Policy Enforcement

Unlike the nested `act` claim in {{!RFC8693}}, the `actor_chain` claim is explicitly designed to be used in access control decisions. Relying Parties and data-plane proxies MAY apply authorization policies based on any entry in the actor chain.

### Policy Examples

The following are illustrative examples of policies that become expressible with the `actor_chain` claim:

**Origin-Based Policy**: Allow access only if the originating actor (index 0) is a trusted orchestrator:

```
actor_chain[0].sub == "https://orchestrator.example.com"
```

**Domain Restriction**: Deny access if any actor in the chain belongs to an untrusted domain:

```
for_all(entry in actor_chain):
  entry.iss in ["https://auth.example.com",
                 "https://auth.partner.com"]
```

**Chain Depth Limit**: Reject tokens with delegation chains longer than a configured maximum:

```
len(actor_chain) <= 5
```

**Residency Requirement**: Require that all actors in the chain have a valid Proof of Residency:

```
for_all(entry in actor_chain):
  entry.por is present AND entry.por is valid
```

**Path-Based Policy**: Allow access only through a specific delegation path:

```
actor_chain[0].sub == "https://orchestrator.example.com" AND
actor_chain[1].sub == "https://planner.example.com"
```

### Integration with Data-Plane Proxies

The flat array structure of `actor_chain` is designed for efficient processing by data-plane proxies such as Envoy, Istio sidecars, and API gateways. Proxies can:

1. Extract the `actor_chain` array from the JWT payload with a single JSON path expression.
2. Iterate linearly over the entries without recursive descent.
3. Index specific entries by position (e.g., `actor_chain[0]` for the originator).
4. Compute `len(actor_chain)` for depth-based policies without parsing nested structures.
5. Emit structured log entries per Actor Chain Entry for distributed tracing and forensic analysis.

# Chain Integrity Verification

Verification of the actor chain operates at two levels, reflecting the data-plane / audit-plane separation.

## Data-Plane Verification

A Relying Party receiving a token with the `actor_chain` claim MUST perform the following verification steps at request time:

1. **JWT Signature Verification**: Verify the outer JWT signature per standard JWT processing rules. This provides integrity for the entire token, including the `actor_chain` and `actor_chain_root` (if present).

2. **Structural Validation**: Verify that `actor_chain` is a JSON array with at least one element. Verify that each element contains the required identity fields (`sub`, `iss`, `iat`).

3. **PoR Verification** (if present):
    - Verify each PoR assertion according to {{!I-D.draft-mw-spice-transitive-attestation}}.

4. **Policy Evaluation**:
    - Apply local authorization policy against the verified actor chain.

If any verification step fails, the Relying Party MUST reject the token.

## Tiered Verification

The appropriate level of actor chain checking depends on the risk level of the operation:

| Risk Level | Data-Plane (sync) | Audit-Plane (async) | Use Case |
| :--- | :--- | :--- | :--- |
| Low | Verify JWT signature | — | Read operations |
| Medium | Verify JWT signature + actor identities | — | Create/update |
| High | Verify JWT signature + actor identities | Full forensic verification via registry | Delete, transfer, admin |
| Critical | Verify JWT signature + actor identities | Full forensic + cross-chain (intent + inference) | Regulatory, cross-border settlements |

## Audit-Plane Verification (Forensic)

For forensic analysis, regulatory compliance, or zero-trust verification, an auditor retrieves the full chain from the Actor Chain Registry and performs:

1. **Retrieve entries**: Discover the Actor Chain Registry endpoint via the AS's metadata (`governance_registry_endpoint`, resolved from the token's `iss` claim) and fetch the full actor chain entries using the token's `sid` as the query key. For cross-chain verification, the auditor retrieves Actor, Intent, and Inference registry entries using the shared `sid` value to correlate all three evidence sets.

2. **Per-Entry Signature Verification**: For each entry at index `i`:
    - **Verify chain_sig**: Verify `chain_sig` against the canonical serialization of the entry's identity claims (`sub`, `iss`, `iat`) using the actor's public key (discoverable via `iss` JWKS endpoint or SPIFFE trust bundle). This proves the actor participated in the delegation.

3. **Merkle Root Verification**: Reconstruct the merkle tree from the `chain_sig` leaf nodes and verify that the computed root matches the `actor_chain_root` in the original token.

This two-tier verification model ensures that data-plane latency remains O(1) while full per-actor non-repudiation is available on demand.

# Relation to Other IETF Work

This proposal extends and complements several ongoing efforts:

| Specification | Relationship |
| :--- | :--- |
| **RFC 8693** {{!RFC8693}} | This document extends {{!RFC8693}} by defining `actor_chain` as a replacement for the informational-only nested `act` claim. The `actor_chain` claim is backward-compatible: an AS MAY populate both `act` (for legacy consumers) and `actor_chain` (for chain-aware consumers). |
| **Transitive Attestation** {{!I-D.draft-mw-spice-transitive-attestation}} | Provides the platform attestation proof (agent to local WIA) that complements the delegation proof (agent to actor-chain) provided by this document. |
| **SPICE Architecture** {{!I-D.ietf-spice-arch}} | Defines the overarching workload identity architecture within which this extension operates. |
| **WIMSE Architecture** {{!I-D.ietf-wimse-arch}} | This proposal aligns with the WIMSE delegation and impersonation patterns for distributed microservices architectures. |
| **Attestation-Based Auth** {{!I-D.ietf-oauth-attestation-based-client-auth}} | Provides the client-to-AS attestation mechanism that can be leveraged to populate the hardware-rooted `por` claims in Actor Chain Entries. |
| **SCITT** {{!I-D.ietf-scitt-architecture}} | Verifiable actor chains can be recorded in SCITT transparency logs to provide long-term, tamper-proof auditability of delegation paths. |
| **RATS** {{!RFC9334}} | Provides the attestation foundation for PoR assertions embedded in Actor Chain Entries. |
| **DPoP** {{!RFC9449}} | `actor_chain` complements DPoP by providing delegation-chain context alongside proof-of-possession. |

## Delegation vs. Platform Attestation

This specification addresses the **delegation** axis of agent-to-agent communication, providing a cryptographically verifiable trail of identity delegation across a network of services. In contrast, Transitive Attestation {{!I-D.draft-mw-spice-transitive-attestation}} addresses the **platform attestation** axis of an agent's relationship with its local hosting environment (e.g., a Workload Identity Agent on a TEE-enabled node). 

By embedding platform attestation Proofs of Residency (PoR) within delegation Actor Chain Entries, a Relying Party gains end-to-end assurance that every entity in a global delegation chain is both a recognized identity and is executing within a verified, secure environment.

## Backward Compatibility with RFC 8693

An Authorization Server implementing this extension SHOULD populate both the `act` claim (per {{!RFC8693}} Section 4.1) and the `actor_chain` claim in issued tokens. This ensures that:

- **Legacy consumers** that understand only `act` continue to function correctly, seeing the current actor in the top-level `act` claim.
- **Chain-aware consumers** can use `actor_chain` for fine-grained policy enforcement and audit.

The `act` claim, when present alongside `actor_chain`, MUST identify the same entity as the last entry in the `actor_chain` array.

# Scalability Considerations

## Token Size

The `actor_chain` identity entries are embedded inline in the JWT. Each Actor Chain Entry adds approximately 150-300 bytes (identity claims only; no signatures). For a chain of depth 5, this adds approximately 0.75-1.5KB to the token. The `actor_chain_root` adds a fixed 44 bytes regardless of chain depth. Authorization Servers SHOULD enforce `max_chain_depth` to bound token size. A RECOMMENDED default maximum of 10 entries limits the actor chain contribution to approximately 3KB.

For the CWT representation, Actor Chain Entries use CBOR maps with integer keys, and `chain_sig` in the registry uses COSE_Sign1 {{!RFC9052}}, further reducing overhead.

## Signature Verification Cost

Data-plane signature verification cost is O(1) — the Relying Party verifies only the outer JWT signature. The `actor_chain_root` is trusted as part of the signed payload. Per-actor signature verification is deferred to the audit plane, where it is O(n) but occurs asynchronously and only when needed.

## Verification Caching

Relying Parties MAY cache actor chain verification results, keyed by the `actor_chain_root` (which uniquely identifies the complete chain). A cached verification result is valid for the lifetime of the enclosing JWT (`exp` claim).

## Trust Model

The `actor_chain` provides two layers of integrity serving different planes:

1. **Data plane** — AS outer signature (JWT/CWT): The Authorization Server signs the entire token, including the `actor_chain` identity entries and the `actor_chain_root`. If the Relying Party trusts the AS, this single signature provides sufficient assurance for real-time access control decisions.

2. **Audit plane** — Per-actor signatures (registry): Each actor's `chain_sig` in the registry proves that specific actor participated in this specific delegation path. This evidence is independently verifiable and non-repudiable — a compromised AS cannot fabricate an actor's `chain_sig` without that actor's private key.

The `actor_chain_root` binds these two planes: it is a signed claim in the token AND the merkle root of the registry signatures. Any tampering with either plane is detectable.

### Multi-AS Identity Federation

In federated deployments, a delegation chain may span multiple Authorization Servers. For example: `b (AS1) -> a (AS1) -> c (AS1) -> f (AS2) -> d (AS2) -> e (AS2)`.

The data-plane token is signed by whichever AS issued the final token (AS2 in this example). For real-time access control, the Relying Party trusts AS2. For audit-plane verification — such as confirming that `b` actually initiated the chain through AS1 — the auditor retrieves the registry entries and verifies each actor's `chain_sig` against that actor's public key, discoverable via the `iss` claim (JWKS endpoint) or SPIFFE ID (trust bundle). No single AS needs to be trusted for the entire chain.

Federated deployments SHOULD:

- Publish actor signing keys via standard discovery mechanisms (JWKS endpoints, SPIFFE trust bundles).
- Include `kid` or `jwk` in each `chain_sig` JWS header for key resolution.
- Enforce cross-domain trust policies on the `iss` field of each Actor Chain Entry.

### Cross-AS Ordering and Completeness (Open Work Item)

In the current design, each actor signs only its own identity claims (`chain_sig` is standalone). The merkle tree enforces ordering within a single AS's domain, but when entries cross an AS boundary — for example, AS2 receiving entries from AS1 — the receiving AS could theoretically reorder or omit entries from the originating AS. Per-actor signatures remain independently verifiable (participation is provable), but ordering and completeness across AS boundaries are not cryptographically enforced.

The leading candidate solution is a **subtree root model**: instead of rebuilding a flat merkle tree over all `chain_sig` values, the receiving AS (AS2) uses the originating AS's signed root (`r_prior`) as a leaf node in its own tree:

```
Within AS1:  r2 = Merkle(σ_0, σ_1)
At AS2:      r3 = Merkle(r2, σ_2)
```

This cryptographically binds AS2's tree to AS1's ordering and completeness — reordering or dropping any of AS1's entries would change `r2`, which would change `r3`. The approach adds zero token bloat (the token still carries only the final root) and naturally mirrors the federation topology.

A future version of this document will specify the subtree root construction, its interaction with the registry response schema, and the recursive verification algorithm. This is tracked as an open work item.

## Chain Integrity

The merkle tree structure in the registry provides tamper evidence for the entire delegation path. The `chain_sig` values form the ordered leaf nodes of the merkle tree, and the resulting `actor_chain_root` is committed in the signed token. Insertion, deletion, or reordering of entries changes the leaf positions, producing a different merkle root that no longer matches the token's `actor_chain_root`. A fabricated entry would also fail verification because the attacker cannot produce a valid `chain_sig` without the actor's private key.

## Replay Protection

Each Actor Chain Entry includes an `iat` (issued-at) timestamp. Relying Parties SHOULD enforce a maximum age on Actor Chain Entries to prevent replay of stale chains. Additionally, the standard JWT claims `exp` and `nbf` on the enclosing token provide overall token-level freshness.

## Chain Depth Limits

Unbounded actor chains pose a risk of token size explosion and processing overhead. Authorization Servers SHOULD enforce a configurable maximum chain depth (`max_chain_depth`). A RECOMMENDED default maximum is 10 entries. Relying Parties MAY independently enforce their own chain depth limits.

## Key Management

Each actor in the chain signs its own identity claims with its private key. Actors SHOULD use short-lived keys and/or hardware-protected keys (e.g., via the PoR mechanism). The same signing key MAY be used for the actor's `chain_sig` in the actor chain, its contributions to the Intent Chain {{!I-D.draft-mw-spice-intent-chain}}, and the Inference Chain {{!I-D.draft-mw-spice-inference-chain}}, providing a unified key management model across all three governance chains.

## Privacy of Prior Actors

The `actor_chain` exposes the identities of all actors in the delegation path to every Relying Party that receives the token. While this is necessary for certain audit and policy requirements, it may conflict with privacy goals. For example, in a chain `a -> b -> c -> d -> e`, the originating actor `a` may require its identity to be hidden from `e` while still ensuring the integrity of the delegation.

Deployments SHOULD consider the following anonymization and privacy-preserving techniques:

### Pseudonymous Identifiers

Instead of using globally unique or stable identifiers (like email addresses or client IDs), the Authorization Server (AS) can issue pairwise pseudonyms for actors. In the chain `a -> b -> c -> d -> e`:
- The AS replaces `sub: "a"` with a pseudonym `sub: "pseudo-xyz"` that is only meaningful to the AS.
- Relying Party `e` sees that the chain started with a verified actor, but does not know it was `a`.
- The AS maintains a mapping to allow for forensic reconstruction if authorized.

### Selective Disclosure (SD-JWT)

Selective Disclosure for JWTs (SD-JWT) {{!I-D.ietf-oauth-selective-disclosure-jwt}} is a promising mechanism for hiding actor identities from downstream Relying Parties while preserving chain integrity. However, the interaction between SD-JWT Disclosure mechanics and per-actor `chain_sig` signatures requires further specification. A future version of this document will define how `chain_sig` is computed when Actor Chain Entries contain selectively disclosed claims. This is tracked as an open work item.

### Identity Bridging for Anonymity

An Identity Bridge {{!I-D.ietf-spice-arch}} MAY act as an "Anonymizer" by performing a token exchange that replaces sensitive predecessor entries in the `actor_chain` with generic or pseudonymous identifiers, while still vouching for the chain's security properties.

### Encryption (JWE)

The entire `actor_chain` claim can be encrypted using JWE {{!RFC7516}} so that only the final intended audience `e` can decrypt it, preventing intermediate actors like `b`, `c`, and `d` from seeing the IDs of their predecessors. Alternatively, the chain can be nestedly encrypted for different parties in the path.

## Confused Deputy Mitigation

A confused deputy attack—where a legitimate actor is tricked into delegating to a malicious downstream—is detectable because the malicious downstream actor's identity appears in the chain, providing forensic evidence of the attack path. The malicious actor's own cryptographic `chain_sig` (retrievable from the registry) provides non-repudiable evidence of its participation.

# IANA Considerations

## JSON Web Token Claims Registration

This document requests registration of the following claims in the "JSON Web Token Claims" registry established by {{!RFC7519}}:

- **Claim Name**: `actor_chain`
- **Claim Description**: A Cryptographically Verifiable Actor Chain — an ordered array of actor identity entries representing the complete delegation chain.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `actor_chain_root`
- **Claim Description**: merkle root hash of per-actor cryptographic signatures in the actor chain.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

## CBOR Web Token Claims Registration

This document requests registration of the following claims in the "CBOR Web Token (CWT) Claims" registry established by {{!RFC8392}}:

- **Claim Name**: `actor_chain`
- **Claim Description**: A Cryptographically Verifiable Actor Chain.
- **CBOR Key**: TBD (e.g., 40)
- **Claim Type**: array
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `actor_chain_root`
- **Claim Description**: merkle root hash of per-actor COSE_Sign1 signatures.
- **CBOR Key**: TBD (e.g., 41)
- **Claim Type**: tstr
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

# Design Rationale

This section summarizes why the data-plane / audit-plane separation with merkle root binding was chosen for the actor chain.

## Why Not Inline Per-Actor Signatures?

An earlier design included per-actor `chain_sig` directly in each Actor Chain Entry within the token. This approach was rejected for three reasons:

1. **Token size**: Each JWS `chain_sig` adds ~200-300 bytes per entry. For a chain of depth 6, this adds ~1.5-2KB to every token — significant for high-throughput data planes and constrained IoT devices.

2. **Data-plane latency**: Verifying O(n) signatures per request is unnecessary when the Relying Party trusts the issuing AS. Most data-plane decisions require only the actor identities, not cryptographic proof of participation.

3. **Redundancy**: The AS already signs the entire token. Inline per-actor signatures duplicate the integrity guarantee for the common case where the RP trusts the AS.

## Why Per-Actor Signatures At All?

Per-actor signatures are essential for governance because:

1. **Non-repudiation**: An actor cannot deny having participated in a delegation chain. This is critical for regulatory compliance and post-incident forensic analysis.

2. **Multi-AS trust**: In federated deployments (e.g., `b (AS1) -> a (AS1) -> c (AS1) -> f (AS2) -> d (AS2) -> e (AS2)`), no single AS can vouch for the entire chain. Per-actor signatures allow an auditor to verify each actor's participation independently of any AS.

3. **Governance alignment**: The Intent Chain and Inference Chain specifications already require per-actor signatures for content and computation provenance. Without per-actor signatures in the actor chain, the WHO dimension of the governance framework would lack the same level of assurance as WHAT and HOW.

## Why the merkle Root?

The merkle root (`actor_chain_root`) provides the binding between the data-plane token and the audit-plane registry without inflating the token. It has constant size (44 bytes) regardless of chain depth. An auditor verifies the merkle root by reconstructing it from the registry's `chain_sig` values — if the computed root matches the token's `actor_chain_root`, the registry evidence is proven authentic.

This is the same pattern used by the Intent Chain (`intent_root`) and Inference Chain (`inference_root`), creating a unified, architecturally consistent governance framework across all three chains.

## Registry Availability

Deployments where the Actor Chain Registry is unavailable (network partition, registry outage) do not affect data-plane operation — the token's AS-signed `actor_chain` entries are sufficient for real-time access control. The `actor_chain_root` in the signed token acts as a commitment: even during a registry outage, the signed evidence cannot be tampered with because the root is fixed at token issuance.

For high-availability requirements, deployments SHOULD:

- Replicate registry entries across availability zones.
- Use append-only log services designed for high durability (e.g., SCITT transparency logs).
- Cache recently-verified registry entries at the audit plane.

## Registry Hosting

The Actor Chain Registry is an append-only log partitioned by session (`sid`). Per-session entries accumulate as token exchanges occur (one entry per actor per session), and each entry is small (~200-400 bytes including compact JWS `chain_sig`).

A federated IAM/IdM platform (e.g., Keycloak, Microsoft Entra, Okta, PingFederate) is a natural host for the Actor Chain Registry because:

- The Authorization Server already mediates every token exchange ({{!RFC8693}}) and can append registry entries as a side-effect of token issuance.
- IAM platforms already manage the signing key infrastructure (JWKS endpoints, SPIFFE trust bundles) needed to verify `chain_sig` values.
- Federation and cross-domain trust — the core of multi-AS actor chains — are the IAM's primary competency.

Most enterprise IAM/IdM platforms support configurable data stores. To host the Actor Chain Registry, the data store MUST be configured for append-only semantics:

- **No update or delete** of registry entries after creation.
- **Session-scoped partitioning** (`sid`) for isolation and efficient retrieval.
- **Immutable storage backends** such as append-only database tables, write-once object storage (e.g., S3 Object Lock), Kafka topics with log compaction disabled, or SCITT transparency logs.

### Credential Isolation

Registry entries MUST NOT contain OAuth tokens, bearer credentials, or signing keys. The relationship between tokens and registry entries is one-directional: the token's `sid` claim identifies the session whose entries are stored in the registry, but the registry MUST NOT store or reference the token itself. This separation ensures that compromise of the registry does not expose bearer credentials that could be used for unauthorized access.

An IAM/IdM platform that co-locates token issuance and registry storage MUST enforce strict access control boundaries between the token store and the registry store. The token MUST NOT be reconstructable from registry entries alone — registry entries contain only identity claims and per-actor signatures, never the complete token payload or the AS signing key.

### Registry Discovery

The Actor Chain Registry endpoint is NOT carried in the token. Instead, it is discovered via the Authorization Server's metadata, consistent with standard OAuth 2.0 discovery conventions.

The AS MUST publish a `governance_registry_endpoint` field in its Authorization Server Metadata ({{!RFC8414}}). This endpoint serves as the base URL for all governance registries (Actor, Intent, Inference).

A Relying Party or auditor discovers the registry as follows:

1. Resolve the `iss` claim from the token to the AS's metadata document (e.g., `{iss}/.well-known/oauth-authorization-server`).
2. Extract the `governance_registry_endpoint` value from the metadata.
3. Query the registry using the token's `sid` claim as the session key.

The registry endpoint MUST support retrieval by `sid` and chain type. A GET request to the governance registry endpoint returns a JSON object containing the `sid`, the computed `actor_chain_root`, and the full `entries` array:

```
GET {governance_registry_endpoint}/actor?sid={sid}
```

Response:

```json
{
  "sid": "session-123",
  "actor_chain_root": "sha256:9f86d08...",
  "entries": [
    {
      "sub": "https://orchestrator.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000010,
      "chain_sig": "eyJhbGciOiJFUzI1NiIsImt..."
    }
  ]
}
```

In a federated IAM deployment, the governance registry endpoint MAY serve all three chain types under a unified base:

```
GET {governance_registry_endpoint}/actor?sid={sid}
GET {governance_registry_endpoint}/intent?sid={sid}
GET {governance_registry_endpoint}/inference?sid={sid}
```

Alternatively, separate endpoints MAY be published for each chain type (e.g., `governance_actor_registry_endpoint`, `governance_inference_registry_endpoint`) when inference proof sizes require a separate storage backend.

Deployments that omit `actor_chain_root` (single-AS, no governance) require no registry infrastructure beyond the Authorization Server's existing token exchange capability.

{backmatter}

<reference anchor="I-D.ietf-spice-arch" target="https://datatracker.ietf.org/doc/html/draft-ietf-spice-arch">
  <front>
    <title>Secure Patterns for Internet CrEdentials (SPICE) Architecture</title>
    <author initials="Y." surname="Sheffer" fullname="Yaron Sheffer"/>
    <date month="October" day="21" year="2024"/>
  </front>
</reference>

<reference anchor="I-D.draft-mw-spice-intent-chain" target="https://datatracker.ietf.org/doc/html/draft-mw-spice-intent-chain">
  <front>
    <title>Cryptographically Verifiable Intent Chain for AI Agent Content Provenance</title>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <date month="March" day="7" year="2026"/>
  </front>
</reference>

<reference anchor="I-D.draft-mw-spice-inference-chain" target="https://datatracker.ietf.org/doc/html/draft-mw-spice-inference-chain">
  <front>
    <title>Cryptographically Verifiable Inference Chain for AI Agent Computational Provenance</title>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <date month="March" day="7" year="2026"/>
  </front>
</reference>

<reference anchor="I-D.ietf-spice-s2s-protocol" target="https://datatracker.ietf.org/doc/html/draft-ietf-spice-s2s-protocol">
  <front>
    <title>SPICE Service to Service Authentication</title>
    <author initials="P." surname="Howard" fullname="Pieter Howard"/>
    <date month="October" day="21" year="2024"/>
  </front>
</reference>

<reference anchor="I-D.draft-mw-spice-transitive-attestation" target="https://datatracker.ietf.org/doc/html/draft-mw-spice-transitive-attestation">
  <front>
    <title>Transitive Attestation for Workload Proof of Residency</title>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <date month="February" day="21" year="2025"/>
  </front>
</reference>

<reference anchor="I-D.ietf-oauth-selective-disclosure-jwt" target="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt">
  <front>
    <title>Selective Disclosure for JWTs (SD-JWT)</title>
    <author initials="D." surname="Fett" fullname="Daniel Fett"/>
    <date month="October" day="7" year="2024"/>
  </front>
</reference>

<reference anchor="RFC8392" target="https://www.rfc-editor.org/info/rfc8392">
  <front>
    <title>CBOR Web Token (CWT)</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="E." surname="Wahlstroem" fullname="Erik Wahlstroem"/>
    <author initials="S." surname="Erdtman" fullname="Samuel Erdtman"/>
    <author initials="H." surname="Tschofenig" fullname="Hannes Tschofenig"/>
    <date year="2018" month="May"/>
  </front>
  <seriesInfo name="RFC" value="8392"/>
</reference>

<reference anchor="RFC9052" target="https://www.rfc-editor.org/info/rfc9052">
  <front>
    <title>CBOR Object Signing and Encryption (COSE): Structures and Process</title>
    <author initials="J." surname="Schaad" fullname="Jim Schaad"/>
    <date year="2022" month="August"/>
  </front>
  <seriesInfo name="RFC" value="9052"/>
</reference>

<reference anchor="OIDC.BackChannel" target="https://openid.net/specs/openid-connect-backchannel-1_0.html">
  <front>
    <title>OpenID Connect Back-Channel Logout 1.0</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="J." surname="Bradley" fullname="John Bradley"/>
    <date year="2022" month="September"/>
  </front>
</reference>
