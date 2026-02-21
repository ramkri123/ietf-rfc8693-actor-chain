# SPICE: Cryptographically Verifiable Actor Chain for OAuth 2.0 Token Exchange

[![IETF Draft](https://img.shields.io/badge/IETF-Draft-blue.svg)](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This repository contains the IETF Internet-Draft proposing the **`actor_chain`** claim — a **Cryptographically Verifiable Actor Chain** extension to **OAuth 2.0 Token Exchange** [[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)] for the **Secure Patterns for Internet CrEdentials (SPICE)** framework.

The `actor_chain` claim replaces the informational-only nested `act` claim with a **tamper-evident, ordered list of all actors** in a delegation chain, enabling **fine-grained data-plane policy enforcement** and a **cryptographic audit trail** across multi-hop workload delegation — particularly for AI agent-to-agent workloads.

## The Problem: RFC 8693 Actor Limitations

RFC 8693 defines the `act` (actor) claim for expressing delegation in JWTs. While nesting `act` within `act` can represent prior actors, the specification explicitly states:

> *"Prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions."*

This creates critical gaps for modern AI agent workloads:

| Gap | Impact |
|:---|:---|
| **No cryptographic audit trail** | Prior actors are self-reported `sub` strings with no signatures — the chain can be tampered with undetectably |
| **No data-plane policy enforcement** | Resource Servers cannot write authorization policies based on the delegation path |
| **Dynamic AI agent topologies** | AI agents connect dynamically; the full chain identity — not just the last hop — is security-critical |
| **Poor debuggability** | Deeply nested JSON objects are difficult to parse, index, and query in high-throughput data planes |

## The Solution: The `actor_chain` Claim

The `actor_chain` claim is a **flat JSON array** of Actor Chain Entries, ordered chronologically from originating actor (index 0) to current actor (last index). Each entry contains:

- **`sub`** / **`iss`** / **`iat`** — Identity and timing claims
- **`chain_digest`** — SHA-256 hash of all preceding entries (hash-chain)
- **`chain_sig`** — Compact JWS signature by the actor over its `chain_digest`
- **`por`** (optional) — Proof of Residency binding the actor to a hardware-rooted environment

### Example

```json
{
  "sub": "user@example.com",
  "actor_chain": [
    {
      "sub": "https://orchestrator.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000010,
      "por": { "wia_kid": "spiffe://example.com/wia/node-1" },
      "chain_digest": "sha256:mno345...",
      "chain_sig": "eyJhbGciOiJFUzI1NiIs..."
    },
    {
      "sub": "https://planner.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000030,
      "chain_digest": "sha256:def456...",
      "chain_sig": "eyJhbGciOiJFUzI1NiIs..."
    },
    {
      "sub": "https://tool-agent.example.com",
      "iss": "https://auth.example.com",
      "iat": 1700000050,
      "chain_digest": "sha256:jkl012...",
      "chain_sig": "eyJhbGciOiJFUzI1NiIs..."
    }
  ]
}
```

### Data-Plane Policy Examples

The flat array structure enables policies that are impossible with nested `act`:

```
# Origin-based: only allow if orchestrator initiated the chain
actor_chain[0].sub == "https://orchestrator.example.com"

# Domain restriction: all actors must be from trusted issuers
for_all(entry in actor_chain): entry.iss in trusted_issuers

# Depth limit: reject chains longer than 5
len(actor_chain) <= 5

# Residency: all actors must have hardware-rooted PoR
for_all(entry in actor_chain): entry.por is present
```

## Backward Compatibility

The `actor_chain` claim is **backward-compatible** with RFC 8693. An Authorization Server MAY populate both `act` (for legacy consumers) and `actor_chain` (for chain-aware consumers) in the same token.

## Relation to Transitive Attestation

The optional `por` field in each Actor Chain Entry integrates with the **Transitive Attestation** draft ([draft-mw-spice-transitive-attestation](https://datatracker.ietf.org/doc/draft-mw-spice-transitive-attestation/)), providing hardware-rooted Proof of Residency at every hop in the delegation chain. Together, the two drafts enable chains where every actor is both **identity-verified** and **residency-proven**.

## Building the Draft

The draft is written in Markdown and uses `mmark` and `xml2rfc` for conversion.

### Prerequisites
- [mmark](https://github.com/mmark-md/mmark)
- [xml2rfc](https://pypi.org/project/xml2rfc/)

### Build Commands
```bash
# Generate TXT, HTML, and XML outputs
make

# Clean build artifacts
make clean
```

## Contributing

This is an active IETF submission. Feedback is welcome via GitHub issues or the [SPICE mailing list](https://www.ietf.org/mailman/listinfo/spice).
