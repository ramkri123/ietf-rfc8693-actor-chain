# End-to-End Federated Actor Chain Flow

**Scenario:** `a → b → c → d` where `a, b ∈ AS₁` and `c, d ∈ AS₂`

**Actors vs. Audience:** Each entity in the chain plays one or both roles:

| Entity | Audience (receives token) | Actor (signs + exchanges) |
|:---|:---|:---|
| `a` | — | ✅ Actor only (originator) |
| `b` | T₁ | ✅ Both — verifies T₁, then signs and exchanges for T₂ |
| `c` | T₂ | ✅ Both — verifies T₂, then signs and exchanges for T₃ |
| `d` | T₃ | Audience only (terminal RP) |

Only actors (`a`, `b`, `c`) sign identity claims, appear in `actor_chain`, and get Merkle tree leaves. The terminal RP (`d`) consumes the token but has no chain entry. If `d` delegates onward, it becomes an actor.

**Planes:**

| Plane | When | What |
|:---|:---|:---|
| **Data Plane** (green) | Every hop | Receive token, verify JWT — O(1) |
| **Control Plane** (blue) | Token exchange | Sign identity, verify, store, build Merkle, issue token |
| **Audit Plane** (tan) | On-demand, async | Cross-chain verification, forensic audit |

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
        AS1->>R1: Store(sid, {a, σ₀})
        AS1->>AS1: r₁ = Merkle(σ₀)
        AS1->>a: T₁ = JWT_AS₁{chain:[a], root:r₁, sid}
    end

    Note over a, b: Step 2 — Same-Domain Hop (AS₁)
    rect rgb(230, 245, 230)
        Note right of a: Data Plane
        a->>b: T₁
        b->>b: Verify JWT_AS₁(T₁)
    end
    rect rgb(225, 235, 250)
        Note right of b: Control Plane
        b->>b: σ₁ = Sign(canon(b), sk_b)
        b->>AS1: TokenExchange(subject=T₁, actor={b, σ₁})
        AS1->>AS1: Verify T₁, verify σ₁ against pk_b
        AS1->>R1: Store(sid, {b, σ₁})
        AS1->>AS1: r₂ = Merkle(σ₀, σ₁)
        AS1->>b: T₂ = JWT_AS₁{chain:[a,b], root:r₂, sid}
    end

    Note over b, AS2: Step 3 — Cross-Domain Hop (AS₁ → AS₂)
    rect rgb(230, 245, 230)
        Note right of b: Data Plane
        b->>c: T₂
        c->>c: Discover AS₁ JWKS via iss(T₂)
        c->>c: Verify JWT_AS₁(T₂)
    end
    rect rgb(225, 235, 250)
        Note right of c: Control Plane
        c->>c: σ₂ = Sign(canon(c), sk_c)
        c->>AS2: TokenExchange(subject=T₂, actor={c, σ₂})
        AS2->>AS2: Discover AS₁ JWKS, verify JWT_AS₁(T₂)
        AS2->>AS2: Extract r₂ = actor_chain_root from T₂
        AS2->>AS2: Verify σ₂ against pk_c
        AS2->>R2: Store(sid, {c, σ₂})
        AS2->>AS2: r₃ = Merkle(r₂, σ₂)
        AS2->>c: T₃ = JWT_AS₂{chain:[a,b,c], root:r₃, sid}
    end

    Note over c, d: Step 4 — Final RP
    rect rgb(230, 245, 230)
        Note right of c: Data Plane
        c->>d: T₃
        d->>d: Verify JWT_AS₂(T₃)
        d->>d: Evaluate policy on actor_chain
    end

    Note over AS1, R2: Audit Plane (async, on-demand)
    rect rgb(245, 235, 220)
        Note right of d: RP Forensic Audit (recursive)
        d->>d: Archive T₃ (actor_chain=[a,b,c], root=r₃)
        d->>R2: GET /actor?sid={sid}
        R2-->>d: {entries:[{c,σ₂}], prior_root:r₂}
        d->>R1: GET /actor?sid={sid}
        R1-->>d: {entries:[{a,σ₀},{b,σ₁}]}
        d->>d: Assert entries match actor_chain order: a→b→c
        d->>d: Verify σ₀(pk_a), σ₁(pk_b), σ₂(pk_c)
        d->>d: Reconstruct r₂ = Merkle(σ₀,σ₁)
        d->>d: Reconstruct r₃ = Merkle(r₂, σ₂)
        d->>d: Assert r₃ == actor_chain_root in T₃
    end
```

## Simplified Crypto Model

### Per-Actor Signature (standalone — no cumulative hashing)

Each actor signs only its own identity claims:

```
σ_i = Sign(canon(sub_i, iss_i, iat_i), sk_i)
```

No dependency on predecessors. One hash, one sign, regardless of chain depth.

### Merkle Root (subtree model)

Within a single AS, the Merkle tree is built from `chain_sig` leaves:

```
AS₁: r₁ = Merkle(σ₀)
     r₂ = Merkle(σ₀, σ₁)
```

Across AS boundaries, the receiving AS uses the upstream root as a leaf:

```
AS₂: r₃ = Merkle(r₂, σ₂)    ← r₂ trusted from verified JWT
```

This cryptographically binds AS₂'s tree to AS₁'s ordering — reordering or dropping any of AS₁'s entries changes `r₂`, which changes `r₃`. Zero token bloat (token still carries only the final root).

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
| T₃ | AS₂ | `[a, b, c]` | `r₃ = Merkle(r₂, σ₂)` — subtree binding |

## What Lives Where

| Location | Contains | Discovered Via |
|:---|:---|:---|
| **Token** | `actor_chain` entries, `actor_chain_root`, `sid` | Inline |
| **AS metadata** | `governance_registry_endpoint` | `iss` → `.well-known` |
| **R₁ (AS₁)** | `{σ₀, σ₁}` — local entries | AS₁ metadata + `sid` |
| **R₂ (AS₂)** | `{σ₂}` + `prior_root: r₂` — local entry + upstream binding | AS₂ metadata + `sid` |

## Security Properties

| Property | Mechanism |
|:---|:---|
| **Participation proof** | Per-actor standalone σ_i (unforgeable without sk_i) |
| **Ordering proof (within AS)** | Merkle tree over ordered leaves (root pinned in signed token) |
| **Completeness (within AS)** | Merkle root changes if any leaf added/removed |
| **Cross-AS ordering** | Subtree root model: `r₃ = Merkle(r₂, σ₂)` binds AS₂ to AS₁'s ordering |
| **Data-plane integrity** | AS JWT signature |
| **Cross-domain trust** | Each σ_i verifiable via actor's own pk_i, independent of any AS |

## Design Notes (Current Cut)

### Session ID (`sid`) Carry-Forward

The same `sid` value is carried forward across all token exchanges in a delegation chain, including cross-AS hops. AS₂ reuses the `sid` from `T₂` (originated by AS₁) in `T₃` and in its own registry. This means:

- The `sid` acts as a **global correlation key** across all registries.
- An auditor can query both `R₁` and `R₂` with the same `sid` to reconstruct the full chain.
- This assumes `sid` values are globally unique (e.g., UUIDs). No per-AS sid mapping is required.

### Subtree Merkle Root Model

Each AS stores only its own entries and uses the upstream root as a subtree binding:

| AS | Registry Stores | Merkle Root |
|:---|:---|:---|
| AS₁ | `{σ₀, σ₁}` | `r₂ = Merkle(σ₀, σ₁)` — flat tree over local entries |
| AS₂ | `{σ₂}` + `prior_root: r₂` | `r₃ = Merkle(r₂, σ₂)` — subtree binding to AS₁ |

AS₂ trusts `r₂` from the verified JWT (control-plane trust). This cryptographically binds AS₂'s tree to AS₁'s ordering — reordering or dropping any of AS₁'s entries changes `r₂`, which changes `r₃`. Zero token bloat (only the final root is in the token).

### Plane Separation

| Plane | Scope | Operations |
|:---|:---|:---|
| **Data Plane** | Each RP boundary (every hop) | Receive token + verify JWT — O(1) |
| **Control Plane** | Chain building | Sign identity, store, build Merkle, token exchange, issue token |
| **Audit Plane** | Forensic, on-demand | Cross-chain sig verification, recursive Merkle audit |

In cross-AS hops, the receiving AS (AS₂) verifies the originating AS's JWT as a **control-plane** operation (trusting AS₁'s signature). The per-actor signature verification of upstream entries (`σ₀`, `σ₁`) is **audit-plane** work — deferred and async.

### Recursive Audit Verification

An auditor (or RP) performing forensic verification uses the archived token as ground truth:

1. Archive the token — `actor_chain` gives expected ordering, `actor_chain_root` gives expected root
2. Query R₂ (AS₂) by `sid` → gets `{σ₂}` and `prior_root: r₂`
3. Query R₁ (AS₁) by `sid` → gets `{σ₀, σ₁}`
4. Assert entries match `actor_chain` order: a→b→c
5. Verify each `σ_i` against the actor's public key
6. Reconstruct `r₂ = Merkle(σ₀, σ₁)`, then `r₃ = Merkle(r₂, σ₂)`
7. Assert `r₃ == actor_chain_root` in the archived token

## Open Work Items

**Per-AS Session ID Mapping**: An alternative to the carry-forward `sid` model is per-AS sid namespacing, where AS₂ mints its own `sid` and maps it to AS₁'s. This provides namespace sovereignty but requires a mapping table and complicates cross-AS auditing. Deferred to a future version.

**Notes**: The `sid` claim is reused from OpenID Connect Back-Channel Logout 1.0 (not defined in RFC 8693). Registry discovery uses the AS's `.well-known` metadata (`governance_registry_endpoint`), not an in-token claim.
