# End-to-End Federated Actor Chain Flow

**Scenario:** `a → b → c → d` where `a, b ∈ AS₁` and `c, d ∈ AS₂`

## Sequence Diagram

```mermaid
%%{init: {'theme':'default'}}%%
sequenceDiagram
    participant a as a (Actor)
    participant AS1 as AS₁
    participant R1 as Registry₁
    participant b as b (Actor)
    participant c as c (Actor)
    participant AS2 as AS₂
    participant R2 as Registry₂
    participant d as d (RP)

    Note over a, AS1: Step 1 — Chain Origination (AS₁)
    rect rgb(225, 235, 250)
        Note right of a: Control Plane
        a->>a: σ₀ = Sign(canon(a), sk_a)
        a->>AS1: Authenticate + σ₀
        AS1->>AS1: Verify σ₀ against pk_a
    end
    rect rgb(245, 235, 220)
        Note right of AS1: Audit Plane
        AS1->>R1: Store(sid, {a, σ₀})
        AS1->>AS1: r₁ = Merkle(σ₀)
    end
    rect rgb(225, 235, 250)
        Note right of AS1: Control Plane
        AS1->>a: T₁ = JWT_AS₁{chain:[a], root:r₁, sid}
    end

    Note over a, b: Step 2 — Same-Domain Hop (AS₁)
    rect rgb(225, 235, 250)
        Note right of a: Control Plane
        a->>b: T₁
        b->>b: Verify JWT_AS₁(T₁)
        b->>b: σ₁ = Sign(canon(b), sk_b)
        b->>AS1: TokenExchange(subject=T₁, actor={b, σ₁})
        AS1->>AS1: Verify T₁, verify σ₁ against pk_b
    end
    rect rgb(245, 235, 220)
        Note right of AS1: Audit Plane
        AS1->>R1: Store(sid, {b, σ₁})
        AS1->>AS1: r₂ = Merkle(σ₀, σ₁)
    end
    rect rgb(225, 235, 250)
        Note right of AS1: Control Plane
        AS1->>b: T₂ = JWT_AS₁{chain:[a,b], root:r₂, sid}
    end

    Note over b, AS2: Step 3 — Cross-Domain Hop (AS₁ → AS₂)
    rect rgb(225, 235, 250)
        Note right of b: Control Plane
        b->>c: T₂
        c->>c: Discover AS₁ JWKS via iss(T₂)
        c->>c: Verify JWT_AS₁(T₂)
        c->>c: σ₂ = Sign(canon(c), sk_c)
        c->>AS2: TokenExchange(subject=T₂, actor={c, σ₂})
        AS2->>AS2: Discover AS₁ JWKS, verify JWT_AS₁(T₂)
        AS2->>AS1: GET .well-known → governance_registry_endpoint
        AS2->>R1: GET /actor?sid={sid}
        R1-->>AS2: {entries:[{a,σ₀}, {b,σ₁}], root:r₂}
        AS2->>AS2: Verify σ₀(pk_a), σ₁(pk_b), reconstruct r₂
        AS2->>AS2: Verify σ₂ against pk_c
    end
    rect rgb(245, 235, 220)
        Note right of AS2: Audit Plane
        AS2->>R2: Store(sid, [{a,σ₀}, {b,σ₁}, {c,σ₂}])
        AS2->>AS2: r₃ = Merkle(σ₀, σ₁, σ₂)
    end
    rect rgb(225, 235, 250)
        Note right of AS2: Control Plane
        AS2->>c: T₃ = JWT_AS₂{chain:[a,b,c], root:r₃, sid}
    end

    Note over c, d: Step 4 — Final RP (Data Plane + Audit Plane)
    rect rgb(230, 245, 230)
        Note right of c: Data Plane
        c->>d: T₃
        d->>d: Verify JWT_AS₂(T₃)
        d->>d: Evaluate policy on actor_chain
    end
    rect rgb(245, 235, 220)
        Note over d: Audit Plane — O(n), async
        d->>AS2: GET .well-known → governance_registry_endpoint
        d->>R2: GET /actor?sid={sid}
        R2-->>d: {entries:[{a,σ₀},{b,σ₁},{c,σ₂}], root:r₃}
        d->>d: ∀i: verify σ_i against pk_i
        d->>d: Reconstruct Merkle tree, assert root == r₃
    end
```

## Simplified Crypto Model

### Per-Actor Signature (standalone — no cumulative hashing)

Each actor signs only its own identity claims:

```
σ_i = Sign(canon(sub_i, iss_i, iat_i), sk_i)
```

No dependency on predecessors. One hash, one sign, regardless of chain depth.

### Merkle Root (ordering enforced by AS)

The AS constructs the Merkle tree with signatures as ordered leaves:

```
r_n = MerkleRoot(σ_0, σ_1, ..., σ_{n-1})
```

For the 3-actor chain at T₃:

```
node_01 = H(σ_0 || σ_1)
node_2  = H(σ_2 || σ_2)      ← odd leaf, duplicated
r_3     = H(node_01 || node_2)
```

Reordering leaves changes the root → detected by comparing against the signed token.

### Responsibility Split

| Responsibility | Owner | Cost |
|:---|:---|:---|
| Sign own identity | **Actor** | O(1) — 1 hash, 1 sign |
| Validate signatures | **AS** | O(1) per exchange — verify incoming σ_i |
| Build Merkle tree | **AS** | O(n) — at each exchange |
| Store entries | **AS** (registry) | Append-only |
| Verify JWT (data plane) | **RP** | O(1) — 1 sig check |
| Full forensic audit | **Auditor** | O(n) — n sig checks + Merkle reconstruction |

## Token Evolution

| Token | Issuer | `actor_chain` | `actor_chain_root` |
|:---|:---|:---|:---|
| T₁ | AS₁ | `[a]` | `r₁ = Merkle(σ₀)` |
| T₂ | AS₁ | `[a, b]` | `r₂ = Merkle(σ₀, σ₁)` |
| T₃ | AS₂ | `[a, b, c]` | `r₃ = Merkle(σ₀, σ₁, σ₂)` |

## What Lives Where

| Location | Contains | Discovered Via |
|:---|:---|:---|
| **Token** | `actor_chain` entries, `actor_chain_root`, `sid` | Inline |
| **AS metadata** | `governance_registry_endpoint` | `iss` → `.well-known` |
| **Registry** | `{σ_i}` per actor (ordered) | AS metadata + `sid` query |

## Security Properties

| Property | Mechanism |
|:---|:---|
| **Participation proof** | Per-actor standalone σ_i (unforgeable without sk_i) |
| **Ordering proof (within AS)** | Merkle tree over ordered leaves (root pinned in signed token) |
| **Completeness (within AS)** | Merkle root changes if any leaf added/removed |
| **Data-plane integrity** | AS JWT signature |
| **Cross-domain trust** | Each σ_i verifiable via actor's own pk_i, independent of any AS |

## Open Work Items

**Cross-AS Ordering and Completeness**: In the current design, ordering and completeness are enforced within a single AS domain via the Merkle tree. Across AS boundaries, the receiving AS could theoretically reorder or omit entries from the originating AS. The leading candidate solution is a subtree root model where AS2 uses AS1's root as a leaf node: `r3 = Merkle(r2, sig_2)`. This cryptographically binds AS2's tree to AS1's ordering without any token bloat.

**Notes**: The `sid` claim is reused from OpenID Connect Back-Channel Logout 1.0 (not defined in RFC 8693). Registry discovery uses the AS's `.well-known` metadata (`governance_registry_endpoint`), not an in-token claim.
