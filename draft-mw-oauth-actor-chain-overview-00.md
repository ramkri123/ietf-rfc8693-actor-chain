# OAuth Actor Chain: Overview and Design

**Draft:** `draft-mw-oauth-actor-chain-overview-00`  
**Intended category:** Informational  
**Authors:** A Prasad, Ram Krishnan, Diego R. Lopez, Srinivasa Addepalli  
**Date:** 2026-10-04  
**Contact:** A Prasad, ap1729@gmail.com

Markdown reading copy. Standalone XML and text submission copies are maintained separately; this revision has not been submitted to the IETF portal.

## Abstract

A request can pass through several services before reaching an API. OAuth
Token Exchange can represent an actor history in nested `act` claims. It
leaves the rules for constructing that history, limiting its disclosure, and
verifying an actor's own signature to additional profiles. Actor Chain
proposes those rules while keeping the Authorization Server responsible for
issuing tokens and applying policy.

This document provides a new overview of the authors' Actor Chain proposal,
whose Internet-Draft lineage began in SPICE in February 2026. The companion
OAuth Actor Chain: Protocol and Interoperability specification continues the
existing OAuth draft series and defines complete wire formats and processing
requirements.

## Introduction
Applications delegate requests across services. Each receiving service
authorizes calls and may need actor identities, participation evidence, and
disclosure policy. Actors are services or agents acting for the token's subject.

OAuth 2.0 Token Exchange [RFC8693](https://www.rfc-editor.org/rfc/rfc8693.html) can represent history in nested `act`
claims. The Authorization Server (AS) decides whether to include it. Under
RFC 8693 Section 4.1, access control considers top-level claims and the
current actor; earlier actors are informational.

Actor Chain, this proposal, specifies history construction, disclosure,
and verification. A workflow is a sequence of related authorization
transitions. The AS authenticates each new actor, checks authority, and
issues the next token.

The companion protocol specification, [ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md), defines the
complete implementation and interoperability requirements.

### Motivation
A receiving service may trust its immediate caller but still need to know
which earlier services participated in the request. Different recipients
need different parts of that history. These examples illustrate why:

| Disclosure | Example authorization need |
| --- | --- |
| "Full" | A production executor checks the initiating planner and immediate policy broker. The release gateway additionally checks the executor and accepted route through all three. |
| "Subset" | A connector checks the request agent and planner. The repository checks the agent and connector without needing the planner's identity. |
| "Actor-Only" | An external payroll API authorizes the registered payroll connector without learning the internal HR agents that prepared the request. |

Each recipient applies its authorization policy to the disclosed actor history and any required verification evidence. Participation does not prove business approval or successful execution.

Workflow accountability is a separate need. Retained records can help an
authorized auditor correlate accepted actor steps across a workflow, even
when an individual resource needs only its immediate caller.

## Illustrative Workflow
For a report request, orchestrator A asks planner B to select documents;
B invokes connector C, which retrieves records from API D.

For illustration, A/B use Agent2Agent (A2A) [A2A-SPEC](https://a2a-protocol.org/v1.0.0/specification/), B/C use remote Model
Context Protocol (MCP) [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), and D runs on Kubernetes. These are
optional deployment choices.

~~~ text
A orchestrator --A2A--> B planner
B planner --MCP--> C connector --HTTPS--> D document API
~~~

With exchange permissions configured, A obtains a token for B; B exchanges
it for C's token, and C exchanges that for D's. Each exchange records its
requesting actor; each receiver checks its token. Reusing a token for status
checks adds no step.

For "Verified" assurance, C signs an actor proof requesting access to D
from B's accepted step. The AS checks the proof and authority, then signs an
acceptance. C signs the request; the AS signs its acceptance.

## Assurance and Disclosure
**Assurance models:**

- **Declared:** The Authorization Server asserts actor-chain history and continuity.
- **Verified:** Actor-generated cryptographic evidence supports verification of actor participation and chain continuity.

**Disclosure** determines what actor history is visible to the recipient, while assurance determines how that history is substantiated. Verified assurance does not require the recipient to see or independently verify the complete chain.

For the A → B → C → D illustrative workflow:

| **Disclosure** | **History visible to D** | **Assurance** |
| -------------- | ------------------------ | ------------- |
| Full           | A, B, C                  | Declared or Verified |
| Subset         | A and C, if authorized   | Declared or Verified |
| Actor-Only     | C                        | Declared or Verified |

## Token Claims and Example
This example uses "Verified" assurance and "Actor-Only" disclosure:

| Claim | Meaning in C's token for D |
| --- | --- |
| `sub` | The party or context represented by the workflow |
| `aud` | The intended recipient, D |
| `actp` | The profile: `verified-actor-only` |
| `acti` | A random identifier shared by this workflow's tokens |
| `act` | C's identity: issuer and subject pair |
| `actc` | The AS-signed acceptance of C's proof |

This partial JSON Web Token (JWT) omits issuer, lifetime, token identifier, and sender binding.
Angle brackets mark placeholders.

~~~ json
{
  "sub": "workflow-subject-alias",
  "aud": ["https://d.example"],
  "actp": "verified-actor-only",
  "acti": "<random workflow identifier>",
  "act": { "iss": "https://actors.example/c", "sub": "C" },
  "actc": "<acceptance_C>"
}
~~~

`<acceptance_C>` is the complete AS-signed acceptance JWT encoded as a string.
It hashes C's proof and B's acceptance. These fingerprints identify exact
records without embedding them; supplying those records enables substitution
checks.

## Evidence Delivery
D checks the AS's `actc`; C's signature additionally needs C's proof.
Resources advertise requirements through authenticated OAuth Protected
Resource Metadata [RFC9728](https://www.rfc-editor.org/rfc/rfc9728.html). The optional `acte` supplies evidence:

| Field | This example | Alternative |
| --- | --- | --- |
| `coverage` | `current`: C's step | `disclosed`: actors in `act`; `path`: complete "Full" path |
| `delivery` | `inline`: inside the token | `introspection`: authenticated AS retrieval [RFC7662](https://www.rfc-editor.org/rfc/rfc7662.html) |

For "Subset", `disclosed` carries one original proof/acceptance pair per
actor occurrence in `act`. If D requires A/C, it receives and verifies A/C
without B's proof. Another authorized recipient may receive B's evidence
according to its policy. The issuer attests that selected records belong to
this token's accepted path. Signatures prove the requests signed, not adjacency
across omitted actors. `current` verifies C only; `path` independently checks
the complete accepted path.

Inline delivery avoids retrieval but enlarges tokens. Introspection needs
an available endpoint. Missing required evidence or conflicting disclosure
policy causes failure.

Here `v=1` identifies the evidence format; `<proof_C>` is C's signed access
request for D. Each `steps` entry pairs a proof with its acceptance:

~~~ json
{
  "acte": {
    "v": 1,
    "coverage": "current",
    "delivery": "inline",
    "steps": [
      { "proof": "<proof_C>", "acceptance": "<acceptance_C>" }
    ]
  }
}
~~~

D requires this acceptance to equal token `actc`, verifies both signatures,
and matches the acceptance's proof hash to the supplied proof. Current
evidence can hide A/B. `disclosed` uses envelope version 2; each selected
signature is checked, and the final acceptance equals `actc`. Historical
signed targets may reveal omitted services; conflicting privacy requirements
cause failure.

SD-JWT could supply selective field disclosure in a future encoding profile
[RFC9901](https://www.rfc-editor.org/rfc/rfc9901.html); this version preserves ordinary JWT signatures and defines no
SD-JWT wire format.

## Deployment Requirements
Clients, ASs, and verifiers need Actor Chain support. Each receiving service
needs AS authorization to exchange inbound tokens; receiving a sender-bound
token does not transfer the previous actor's key.

MCP's Bearer presentation [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) needs compatible sender binding, such
as certificate-bound mutual TLS [RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html), where permitted. Kubernetes
credentials [K8S-SA](https://kubernetes.io/docs/concepts/security/service-accounts/) authenticate workloads without creating actor proofs.
The protocol specification's "Agent and Workload Integration" section
[ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md) details these requirements. Live interoperability
remains untested.

## Cross-Domain Preservation
Transfer between ASs preserves accepted state and original signatures without
adding an application actor. The protocol specification's "Cross-Domain
Preservation" section [ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md) defines it.

Mapping `read` to destination permission `documents.read` needs destination
authorization. An earlier signature still covers `read`; it does not attest
to the translated meaning. Direct verification of a new step requires its
actor's fresh signature on local values. The same applies to translated
subject and resource names.

## Security and Privacy Considerations
With independently authorized actor keys, valid proofs, and checked linkage,
a malicious AS cannot attribute a covered step to a non-colluding actor.
It can misstate Subset membership, misapply policy, issue other tokens, or
collude. Evidence does not
prove correct execution or faithful interpretation of user intent.

C's exchange-time signature does not establish who presents the token now.
The protocol specification [ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md) uses Demonstrating Proof
of Possession (DPoP) [RFC9449](https://www.rfc-editor.org/rfc/rfc9449.html) to check control of the token-bound key.
Other sender-binding mechanisms need explicit agreement.

Exact retries reuse one acceptance. Separate requests can branch; one
verified path does not prove uniqueness. Full evidence reveals relationships
and timing; workflow identifiers permit correlation. Historical verification
needs retained proofs and key history. Introspection and replay state add
live dependencies.

## Questions for IETF Review
1. Do these use cases justify a common contract beyond RFC 8693?
2. Does issuer-attested membership meet Subset authorization needs?
3. Are disclosure requirements and recipient policy boundaries sufficient?
4. Does cross-domain preservation accurately describe mappings' assurance?

## Design Evolution
The authors' SPICE `-00` (25 February 2026) carried actor signatures in
self-attested tokens [SPICE-ACTOR-CHAIN-00](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/00/). SPICE `-01` (16 March 2026) moved
them to exchange-time proofs with hash-linked AS acceptances
[SPICE-ACTOR-CHAIN-01](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/01/). OAuth `-01` (15 June 2026) continued this work
[OAUTH-ACTOR-CHAIN-01](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/01/). The companion protocol `-02` continues that series
and specifies evidence delivery.

## IANA Considerations
This overview requests no IANA action. Registration requests are defined in
[ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md).

## Informative References

- [A2A-SPEC](https://a2a-protocol.org/v1.0.0/specification/): Agent2Agent Protocol Specification, version 1.0.0.
- [ACTOR-CHAIN-PROTOCOL](draft-mw-oauth-actor-chain-02.md): OAuth Actor Chain: Protocol and Interoperability.
- [K8S-SA](https://kubernetes.io/docs/concepts/security/service-accounts/): Kubernetes Service Accounts.
- [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization): Model Context Protocol Authorization, revision 2026-07-28.
- [OAUTH-ACTOR-CHAIN-01](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/01/): Cryptographically Verifiable Actor Chains for OAuth 2.0 Token Exchange.
- [RFC7662](https://www.rfc-editor.org/rfc/rfc7662.html): OAuth 2.0 Token Introspection.
- [RFC8693](https://www.rfc-editor.org/rfc/rfc8693.html): OAuth 2.0 Token Exchange.
- [RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html): OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
- [RFC9449](https://www.rfc-editor.org/rfc/rfc9449.html): OAuth 2.0 Demonstrating Proof of Possession (DPoP).
- [RFC9728](https://www.rfc-editor.org/rfc/rfc9728.html): OAuth 2.0 Protected Resource Metadata.
- [RFC9901](https://www.rfc-editor.org/rfc/rfc9901.html): Selective Disclosure for JSON Web Tokens.
- [SPICE-ACTOR-CHAIN-00](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/00/): Cryptographically Verifiable Actor Chain for OAuth 2.0 Token Exchange.
- [SPICE-ACTOR-CHAIN-01](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/01/): Cryptographically Verifiable Actor Chains for OAuth 2.0 Token Exchange.
