# Actor Chain — Base Profile: Cryptographic Audit Trail

**Status:** Draft — Design Proposal  
**Date:** 2026-03-14  
**Companion:** [draft-mw-spice-actor-chain](./draft-mw-spice-actor-chain.md)

---

## Problem

### Context

Regulated industries (finance, healthcare, public sector) require **non-repudiable, tamper-evident audit trails** of multi-party AI agent delegations. When Agent B delegates to Agent C to execute a financial transfer on behalf of Agent A, three questions must be answerable months or years later:

1. **WHO** participated at each step of the delegation?
2. **Did each actor knowingly initiate the next hop** — or can they deny it?
3. **Can the audit trail be tampered with** — by any single actor or a small colluding subset?

### Threat: Post-Facto Non-Repudiation Failure

**Attack scenario:**

```
A → B → C → RP  (financial transfer: $10M)

Post-facto: B claims "I never instructed C to perform this transfer."
```

B's strategy:
- B claims its token was intercepted and misused by C
- B claims the `actor_chain` was forged by AS₁ or AS₂
- B denies ever authorising the specific delegation to C

**Why the current full profile doesn't fully prevent this:**

The current design ([draft-mw-spice-actor-chain](./draft-mw-spice-actor-chain.md)) has B sign only its own identity claims:

```
σ_B = Sign(sk_B, canon(sub_B, iss_B, iat_B))
```

B's signature proves B *authenticated* to AS₁ at some point. But it does **not** prove B specifically authorised the delegation **to C** for **this session** (`sid`). An adversarial B could argue:

- "I authenticated to AS₁, but I didn't initiate the call to C — my session was hijacked"
- "σ_B is my identity sig, not an authorisation sig over the specific delegation chain"

**The colluding AS problem:**

Even if B cannot modify `actor_chain` inline (AS₂ would have to collude), a colluding AS₂ *could* fabricate or replay a chain if the only cryptographic check is AS₂'s own JWT signature. If the auditor only trusts AS₂'s JWT, a compromised AS₂ can produce any token it wants.

---

## Solution: Hash-Chain Base Profile

### Core Idea

Each actor signs a **chain-linked commitment** — not just its own identity, but a hash chaining over the previous actor's commitment:

```
hash_chain_sig_A = Sign(sk_A, H(canon(A) || sid))
hash_chain_sig_B = Sign(sk_B, H(hash_chain_sig_A || canon(B) || sid))
hash_chain_sig_C = Sign(sk_C, H(hash_chain_sig_B || canon(C) || sid))
```

Where `canon(X)` = canonical serialisation of X's identity claims (`sub`, `iss`, `iat`).

This means:

- **B's signature is over a commitment that includes A's evidence.** B cannot produce a valid `hash_chain_sig_B` without knowing `hash_chain_sig_A` — i.e., without being present in the live flow.
- **B cannot deny participation** — its private key produced a signature over a value that includes the session identifier and A's commitment. A forged `hash_chain_sig_B` requires B's private key.
- **No single AS can fabricate the chain** — each `hash_chain_sig` is produced by the actor's own key, not the AS. AS₂ does not hold B's private key and cannot produce a valid `hash_chain_sig_B`.

### Token Structure (Base Profile)

Each token carries **two fields** over RFC 8693:

```json
{
  "sub": "https://agent-a.example.com",    // current subject (RFC 8693)
  "act": { "sub": "..." },                 // current actor sub (RFC 8693, optional)
  "sid": "550e8400-e29b...",               // session ID (carry-forward)
  "hash_chain_sig": "<hash_chain_sig_C>",  // chained commitment (base64url)
  "actor_sig": "<σ_C>"                     // actor's own standalone identity sig
}
```

- **`hash_chain_sig`**: The actor's signature over `H(prev_hash_chain_sig || canon(self) || sid)`. For the originator, signed over `H(canon(A) || sid)` (no predecessor).
- **`actor_sig`**: The actor's standalone identity signature `Sign(sk_i, canon(sub_i, iss_i, iat_i))`. Used for individual public-key discovery and verification without needing the chain context.

Token size: **~128–192 bytes** additional, independent of chain depth. Compare to the full profile which grows linearly with chain depth.

### AS Role

The AS at each hop:

1. **Validates** the inbound `hash_chain_sig` against the claimed prior actor's public key (via JWKS/SPIFFE).
2. **Verifies** the new actor's `actor_sig` against its own public key.
3. **Archives the full token** (including `hash_chain_sig` and `actor_sig`) in its registry, indexed by `sid`.
4. **Carries forward** the inbound `hash_chain_sig` value to include in the next actor's commitment input.
5. **Issues** the new token with the updated `hash_chain_sig` and `actor_sig`.

The AS **does not** need to maintain a separate Merkle tree or registry of signatures — the archive of tokens *is* the audit trail.

### Audit Verification (Forensic)

The auditor fetches archived tokens by `sid` from each AS's registry, then performs an **in-order forward traversal**:

```
// Fetch archived tokens
T₁ = AS₁.archive.get(sid)   // hash_chain_sig_A, actor_sig_A
T₂ = AS₁.archive.get(sid)   // hash_chain_sig_B, actor_sig_B
T₃ = AS₂.archive.get(sid)   // hash_chain_sig_C, actor_sig_C

// Verify originator (i=0)
verify actor_sig_A against pk_A
assert hash_chain_sig_A == Sign(sk_A, H(canon(A) || sid))

// Verify i=1 (chain link: B signed over A's commitment)
verify actor_sig_B against pk_B
assert hash_chain_sig_B == Sign(sk_B, H(hash_chain_sig_A || canon(B) || sid))

// Verify i=2 (chain link: C signed over B's commitment)
verify actor_sig_C against pk_C
assert hash_chain_sig_C == Sign(sk_C, H(hash_chain_sig_B || canon(C) || sid))
```

**O(n) verification cost** — one signature verify and one hash check per actor. Each step proves:

1. The actor's private key produced the `hash_chain_sig`
2. The actor was present in the live flow (it knew `prev_hash_chain_sig`)
3. The chain is unbroken — any modification to any step breaks all subsequent links

---

## Security Properties

| Property | Mechanism |
|:---|:---|
| **Non-repudiation of participation** | `hash_chain_sig_B` requires sk_B and live knowledge of `hash_chain_sig_A` |
| **Non-repudiation of ordering** | Each link commits to its predecessor — reordering breaks the chain |
| **AS-forgery resistance** | No AS holds actors' private keys; cannot fabricate `hash_chain_sig` |
| **Colluding AS resistance** | B + AS₂ colluding cannot forge `hash_chain_sig_A` (requires sk_A) |
| **Colluding actors** (B+C) | B+C can collude to fabricate a chain *between them* but cannot insert themselves into A's signed chain without A's key |
| **Session binding** | `sid` in every commitment prevents cross-session replay |
| **Tamper evidence** | Any modification to any actor's claims changes the hash input, breaking all downstream `hash_chain_sig` values |

### Residual Risk: B+C Collusion Against A

If B and C collude post-facto:

- B **cannot** claim it didn't participate — its private key signed `hash_chain_sig_B`
- B **cannot** fabricate a different chain that excludes C — C's sig links to B's commitment
- B **could** claim the *intended action* was different (e.g., "I authorised C for X, not Y")

This risk is addressed by including **intent/scope** in the commitment (see §Future Work below), or by the companion Intent Chain specification.

---

## Comparison: Base Profile vs. Full Profile

| Aspect | Base Profile (this doc) | Full Profile |
|:---|:---|:---|
| **Token fields** | `hash_chain_sig` + `actor_sig` | `actor_chain` array + `actor_chain_root` |
| **Token size** | O(1) — fixed ~192 bytes extra | O(n) — grows with chain depth |
| **Data-plane identity** | ❌ opaque — no inline actor identities | ✅ inline — RP sees all actors |
| **Fast RP policy** | ❌ requires archive query | ✅ O(1) — read from token |
| **Non-repudiation** | ✅ strong — chained commitment | ✅ per-actor sig (not chained) |
| **AS-forgery resistance** | ✅ actors produce own chain links | ✅ actors produce own sigs |
| **Archive dependency** | RP needs archive for audit only | Same |
| **Cross-AS complexity** | Carry-forward hash value (O(1)) | Merkle subtree binding |
| **Audit cost** | O(n) forward traversal | O(n) in-order traversal |
| **Best for** | Finance, compliance, audit trail | Zero-trust access control |

---

## Profile Selection

A deployment chooses its profile at the AS configuration level:

- **Base profile**: AS issues tokens with `hash_chain_sig` + `actor_sig`. No `actor_chain` array.
- **Full profile**: AS issues tokens with `actor_chain`, `actor_chain_root`, optionally with `hash_chain_sig` for the stronger non-repudiation guarantee.
- **Hybrid** (recommended for high-assurance): Both profiles combined — inline identity for fast policy, hash chain for non-repudiation. Adds ~64 bytes per token.

---

## Flow Diagram (Base Profile)

```
Step 1 — Chain Origination
  A: σ_A = Sign(sk_A, canon(A))
     h_A  = Sign(sk_A, H(canon(A) || sid))     // hash_chain_sig_A
  AS₁ archives T₁ = {actor_sig:σ_A, hash_chain_sig:h_A, sid}
  AS₁ → A: T₁

Step 2 — B delegates (same AS)
  B: σ_B = Sign(sk_B, canon(B))
     h_B  = Sign(sk_B, H(h_A || canon(B) || sid))  // commits to h_A
  AS₁ validates h_A (from T₁), validates σ_B
  AS₁ archives T₂ = {actor_sig:σ_B, hash_chain_sig:h_B, sid}
  AS₁ → B: T₂

Step 3 — C delegates (cross-AS)
  C: σ_C = Sign(sk_C, canon(C))
     h_C  = Sign(sk_C, H(h_B || canon(C) || sid))  // commits to h_B
  AS₂ validates JWT_AS₁(T₂), validates h_B, validates σ_C
  AS₂ archives T₃ = {actor_sig:σ_C, hash_chain_sig:h_C, sid}
  AS₂ → C: T₃

Step 4 — RP consumes T₃
  d: Verify JWT_AS₂(T₃)   // O(1) — data plane
     // No actor identities inline; policy requires archive query
     // OR: tolerate opaque chain at data plane, audit later
```

---

## Open Work Items

### Intent/Scope Binding

Currently B's commitment proves *participation* but not *intent*. For financial contexts, it may be valuable to bind the committed action to the chain:

```
h_B = Sign(sk_B, H(h_A || canon(B) || intent_hash || sid))
```

Where `intent_hash = H(amount, recipient, currency, ...)`. This makes B's commitment a **specific authorisation**, not just a presence proof. Defined in the companion intent chain specification.

### Replay Window

The `sid` prevents cross-session replay. An expiry policy (`exp` on the token) limits intra-session replay. Deployments SHOULD enforce a maximum token age at each hop.

### Key Recovery / Compromise

If B's private key is compromised post-facto, an attacker can forge `hash_chain_sig_B` and thereby impersonate B's position in the chain. Standard key management hygiene (HSM, SPIFFE workload attestation, short-lived credentials) mitigates this.

---

## Summary

The base profile provides **O(1) token size** and **strong chained non-repudiation** suitable for finance, compliance, and audit-trail use cases. The cost is loss of inline actor identity — the RP cannot perform fast actor-identity-based policy without an archive query. For deployments where audit trail integrity is the primary requirement and fast identity-based access control is secondary, the base profile is the right choice.

The full profile (inline `actor_chain` + Merkle root) remains the right choice for zero-trust access control environments where the RP needs to evaluate actor identity at every request.
