%%%
title = "Cryptographically Verifiable Actor Chains for OAuth 2.0 Token Exchange"
abbrev = "SPICE-ACTOR-CHAINS"
category = "std"
docname = "draft-mw-spice-actor-chain-11"
ipr = "trust200902"
area = "Security"
workgroup = "SPICE"
keyword = ["actor chain", "spice", "oauth", "rfc8693", "token exchange", "workload identity", "delegation", "AI agents", "MCP", "A2A"]
date = 2026-03-15

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-spice-actor-chain-11"
stream = "IETF"
status = "standard"

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

[normative]
RFC2119 = {}
RFC8174 = {}
RFC7515 = {}
RFC7519 = {}
RFC8392 = {}
RFC8414 = {}
RFC8693 = {}
RFC8785 = {}
RFC6838 = {}
RFC6920 = {}
RFC8949 = {}
RFC9052 = {}

[informative]
RFC9334 = {}
RFC9901 = {}

[informative."I-D.ietf-spice-arch"]
[informative."I-D.ietf-spice-s2s-protocol"]
[informative."I-D.ietf-spice-sd-cwt"]
[informative."I-D.draft-mw-spice-intent-chain"]
[informative."I-D.draft-mw-spice-inference-chain"]
[informative."I-D.draft-mw-spice-transitive-attestation"]
%%%

.# Abstract

This document defines three actor-chain profiles for OAuth 2.0 Token Exchange
{{!RFC8693}}. {{!RFC8693}} permits nested `act` claims, but prior actors remain
informational only and token exchange does not define how a delegation path is
preserved and validated across successive exchanges.

This document defines profile-specific processing for linear multi-hop
workflows. The profiles are Asserted Delegation Path, Committed Delegation
Path, and Commitment-Only Delegation Path.

These profiles preserve the existing meanings of `sub` and `act`, support same-
domain and cross-domain delegation, require sender-constrained tokens, and
provide different tradeoffs among readable chain-based authorization,
cryptographic accountability, auditability, privacy, and long-running workflow
support.

{mainmatter}

# Introduction

In service-to-service, tool-calling, and agent-to-agent systems, a workload
often receives a token, performs work, and then exchanges that token to call
another workload. This pattern appears in microservices, workload identity
systems, MCP-style tool invocation, and AI-agent orchestration pipelines. The
resulting path can span multiple hops and multiple Authorization Servers
(ASes).

{{!RFC8693}} defines token exchange and the `act` claim for the current actor,
but it does not define a standardized model for preserving and validating the
full delegation path across successive exchanges.

This document defines cryptographically verifiable actor-chain profiles for
OAuth 2.0 Token Exchange.

* `sub` continues to identify the token subject.
* `act`, when present, continues to identify the current actor.
* `actor_chain`, when present, carries the ordered delegation path.
* `actor_chain_commitment`, when present, carries cumulative committed chain
  state for stronger tamper evidence and auditability.

The design separates:

* **inline authorization**, where ordinary tokens carry what the next hop needs
  to validate and authorize a request; and
* **proof and audit**, where committed profiles bind each accepted hop to
  actor-signed proofs and cumulative committed state for later verification.

This document is format-agnostic. JWT deployments use JSON and JWS. CWT
deployments use CBOR and COSE.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document also leverages terminology from OAuth 2.0 Token Exchange
{{!RFC8693}}, the SPICE Architecture {{!I-D.ietf-spice-arch}}, and the RATS
Architecture {{!RFC9334}}.

Actor:
: A workload, service, application component, agent, or other authenticated
  entity that receives a token, performs work, and MAY subsequently act toward
  another actor.

Current actor:
: The authenticated entity presently performing token exchange or presenting a
  sender-constrained token to the next hop.

Presenting actor:
: The authenticated actor that presents a sender-constrained token to a
  recipient.

Recipient:
: The actor or resource server identified as the intended target of an issued
  token.

Actor chain:
: The ordered sequence of actors that have acted so far in one workflow
  instance.

Readable chain:
: An `actor_chain` value carried in an ordinary token and visible to downstream
  recipients.

Committed chain state:
: The cumulative cryptographic state that binds prior accepted chain state to a
  newly accepted hop.

Step proof:
: A profile-defined proof signed by the current actor that binds that actor's
  participation to the workflow, prior chain state, and target context.

Workflow identifier (`sid`):
: A stable identifier minted once at workflow start and retained for the
  lifetime of the workflow instance.

Cross-domain re-issuance:
: A second token exchange performed at another domain's Authorization Server in
  order to obtain a local token trusted by the next recipient, without
  extending the actor chain.

Continuity:
: The property that the inbound token is being presented by the actor that the
  chain state indicates should be presenting it.

Append-only processing:
: The rule that a newly acting actor is appended to the prior chain state,
  without insertion, deletion, reordering, or modification of prior actors.

Terminal recipient:
: A recipient that performs work locally and does not extend the actor chain
  further.

Refresh-Exchange:
: A token-exchange operation by the same current actor that refreshes a short-
  lived transport token without appending the actor chain, changing the active
  profile, or generating a new step proof.

# Problem Statement

{{!RFC8693}} defines the top-level `act` claim for the current actor and allows
nested prior actors. However, prior nested `act` claims are informational only
for access-control decisions. In multi-hop systems, especially service-to-
service and agentic systems, that is not sufficient.

Consider:

~~~ text
User -> Orchestrator -> Planner -> Tool Agent -> Data API
~~~

By the time the request reaches the Data API, the immediate caller may be
visible, but the upstream delegation path is not standardized as a policy input
and is not bound across successive token exchanges in a way that can be
independently validated or audited. This creates several concrete gaps:

* downstream policy cannot reliably evaluate the full delegation path;
* cross-exchange continuity is not standardized;
* tampering by an actor and its home AS is not uniformly addressed;
* forensic verification of per-hop participation is not standardized; and
* ordinary tokens may disclose more prior-actor information than some
  deployments are willing to reveal.

# Relationship to RFC 8693 Claims

This specification extends OAuth 2.0 Token Exchange {{!RFC8693}} without
changing the existing meanings of `sub`, `act`, or `may_act`.

The following rules apply:

* `sub` continues to identify the subject of the issued token.
* `act`, when present, MUST identify the current actor represented by the
  issued token.
* `actor_chain`, when present, is the profile-defined ordered list of actors
  that have acted so far in the workflow instance.
* Nested prior `act` claims, if present for compatibility or deployment-
  specific reasons, remain informational only for access-control purposes,
  consistent with {{!RFC8693}}.
* `may_act`, when present in an inbound token, MAY be used by the accepting
  Authorization Server as one input when determining whether the authenticated
  current actor is authorized to perform token exchange for the requested
  target context.

Nothing in this specification redefines the delegation and impersonation
semantics described in {{!RFC8693}}.

# Scope and Model

This document specifies a family of profiles for representing and validating
actor progression across a linear workflow using OAuth 2.0 Token Exchange.

The base workflow model is linear:

~~~ text
A -> B -> C -> D
~~~

The first actor initializes the workflow. Each subsequent actor MAY:

1. validate an inbound token;
2. perform work; and
3. exchange that token for a new token representing itself toward the next hop.

This document defines three profiles:

* **Asserted Delegation Path**, which carries a readable `actor_chain` and
  relies on AS-asserted chain continuity under a non-collusion assumption;
* **Committed Delegation Path**, which preserves a readable `actor_chain` and
  adds actor-signed step proofs plus cumulative committed state; and
* **Commitment-Only Delegation Path**, which omits the readable
  `actor_chain` from ordinary tokens and preserves only cumulative committed
  state.

This document does not define branching or fan-out semantics. A single accepted
prior state yields at most one accepted successor state unless a future
specification defines branching behavior. This intentional linearity keeps the
base profiles simple for replay detection, audit reconstruction, and
interoperability.

# Protocol Overview

## Workflow Progression

The actor chain advances only when an actor acts. Mere receipt of a token does
not append the recipient.

If `A` calls `B`, and `B` later calls `C`, then:

1. `A` begins the workflow and becomes the first acting actor.
2. When `A` calls `B`, `B` validates a token representing `A`.
3. When `B` later exchanges that token to call `C`, `B` becomes the next
   acting actor.
4. `C` is not appended merely because `C` received a token. `C` is appended
   only if `C` later acts toward another hop.

## Same-Domain and Cross-Domain Hops

Within one trust domain, the current actor exchanges its inbound token at its
home Authorization Server, which validates prior state and issues a token for
the next hop.

Across a trust boundary, if the next recipient does not trust the current
Authorization Server directly, the current actor performs a second token
exchange at the next domain's Authorization Server. That second exchange
preserves the already-established chain state and does not append the next
recipient.

## Trust Boundaries

This specification provides different assurances depending on the selected
profile:

* **Asserted Delegation Path**: the issuing AS signature and chain assertion
  are the primary trust anchor.
* **Committed Delegation Path**: readable chain state is preserved and each
  accepted hop is additionally bound to actor-signed proof and committed state.
* **Commitment-Only Delegation Path**: readable prior actors are omitted from
  ordinary tokens, while committed state and actor-signed proofs remain
  available for stronger accountability and later verification.

# Common Requirements

## Common Token Requirements

Tokens issued under any profile defined by this document:

* MUST be short-lived;
* MUST be sender-constrained to the presenting actor; and
* MUST contain:
  * a profile identifier claim `acp`;
  * a workflow identifier claim `sid`;
  * a unique token identifier claim `jti`;
  * an audience value `aud`; and
  * an expiry value `exp`.

Profiles that preserve readable chain state additionally carry `actor_chain`.

Profiles that preserve committed chain state additionally carry
`actor_chain_commitment`.

## Workflow Identifier

The `sid` value:

* MUST be minted once at workflow start by the issuing Authorization Server;
* MUST be generated using a CSPRNG with at least 128 bits of entropy;
* MUST remain unchanged for the lifetime of that workflow instance; and
* MUST NOT be used to signal profile selection.

Profile selection MUST be signaled explicitly using:

* the token request parameter `actor_chain_profile`; and
* the corresponding token claim `acp`.

## Target Context

This specification uses the term `target_context` to refer to the intended
authorization target bound into profile-defined step proofs and receiver
acknowledgments.

`target_context` MUST include `aud`.

A deployment MAY additionally include resource identifiers, operation names,
tool identifiers, method names, request classes, or other target-selection
inputs used by local authorization policy.

If no such additional values are available, `target_context` is identical to
`aud`.

Whenever `target_context` is incorporated into a profile-defined signature or
commitment input, it MUST be canonicalized using JCS in JWT deployments and
deterministic CBOR in CWT deployments before hashing or signing.

## Sender Constraint

A token issued under any profile in this document MUST be sender-constrained to
the actor represented by that token.

A recipient or Authorization Server validating such a token MUST verify the
applicable sender-constrained proof before accepting the token.

Failure of sender-constrained validation MUST cause rejection.

## Actor and Recipient Proof Keys

For committed-chain profiles and for `hop_ack`, any signature used as a
profile-defined proof MUST be generated with an asymmetric key bound to the
authenticated actor or recipient identity by local trust policy.

For a committed-profile step proof, the ActorID represented in the proof, the
key used to sign the proof, and the sender-constrained key used to present the
corresponding token MUST all be bound to the same actor identity. When the same
key is not reused for both functions, the Authorization Server MUST validate an
explicit local binding between the proof-signing key and the sender-constrained
presentation key before accepting the proof.

For `hop_ack`, the recipient ActorID, the key used to sign the acknowledgment,
and any sender-constrained key used by that recipient for the protected
interaction MUST likewise be bound to the same recipient identity.

Shared client secrets MUST NOT be the sole basis for independently verifiable
step proofs or receiver acknowledgments.

A deployment SHOULD reuse the same asymmetric key material used for sender-
constrained token presentation, or another asymmetric key that is
cryptographically bound to the same actor identity.

## Intended Recipient Validation

When a current actor submits an inbound token as a `subject_token` in token
exchange, the accepting Authorization Server MUST verify that the authenticated
current actor was an intended recipient of that inbound token according to local
audience, resource, or equivalent validation rules.

Possession of an inbound token alone is insufficient.

## Replay and Freshness

Recipients and Authorization Servers MUST enforce replay and freshness checks on
inbound tokens according to local policy.

For profiles that use actor-signed step proofs, the accepting Authorization
Server:

* MUST detect replay of a previously accepted step proof within its
  replay-retention window; and
* SHOULD reject a second accepted successor for the same `(sid, prior_state)`
  tuple unless a future branching profile is in use.

## Canonicalization

All profile-defined signed or hashed inputs MUST use a canonical serialization
defined by this specification.

In JWT/JSON deployments, canonical profile-defined proof payloads MUST be
serialized using JCS {{!RFC8785}}. In CWT/CBOR deployments, they MUST be
serialized using deterministic CBOR encoding as defined in {{!RFC8949}},
Section 4.2.

## Actor Identity Representation

This specification requires a canonical representation for actor identity in
profile-defined chain entries and step proofs.

Each actor identifier MUST be represented as an ActorID structure containing
exactly two members:

* `iss`: the issuer identifier naming the namespace in which the actor subject
  value is defined; and
* `sub`: the subject identifier of the actor within that issuer namespace.

For JWT and JSON-based proof payloads, an ActorID is a JSON object with members
`iss` and `sub`, serialized using JCS {{!RFC8785}}.

For CWT and CBOR-based proof payloads, an ActorID is a deterministic CBOR map
with integer label `1` for `iss` and integer label `2` for `sub`.

An ActorID:

* MUST be stable for equality comparison within a workflow instance;
* MUST be bound to the authenticated actor identity used during
  sender-constrained token presentation and token exchange;
* MUST be compared using exact equality of the pair (`iss`, `sub`); and
* SHOULD support pairwise or pseudonymous subject values where deployment
  policy allows.

Readable-chain profiles carry arrays of ActorID values in `actor_chain`.
Privacy-preserving profiles bind ActorID values only inside step proofs and
related evidence. In examples and formulas, `[A,B]` denotes a readable chain of
ActorID values for actors `A` and `B`.

## Artifact Typing

JWT-based artifacts defined by this specification MUST use explicit `typ`
values.

The following values are defined:

* `actc-step-proof+jwt`
* `actc-commitment+jwt`
* `actc-hop-ack+jwt`

Verifiers MUST enforce mutually exclusive validation rules based on artifact
type and MUST NOT accept one artifact type in place of another.

CWT and COSE deployments MUST apply equivalent type discrimination by verifying
the expected artifact class, exact `ctx` value, and artifact-specific payload
structure defined by the relevant binding section of this specification.

## Issued Token Type

Unless another application profile explicitly states otherwise, tokens issued
under this specification are access tokens.

Token exchange responses MUST use the RFC 8693 token type fields consistently
with the underlying representation and deployment.

## Commitment Hash Algorithms

Committed-chain profiles use a named hash algorithm for construction of
`actor_chain_commitment`.

Commitment hash algorithm identifiers are values from the IANA Named
Information Hash Algorithm Registry {{IANA.Hash.Algorithms}}.

Implementations supporting committed-chain profiles MUST implement `sha-256`.
Implementations SHOULD implement `sha-384`.

Every `actor_chain_commitment` object and every committed-profile bootstrap
context MUST carry an explicit `halg` value. Verifiers MUST NOT infer or
substitute `halg` when it is absent.

Verifiers MUST enforce a locally configured allow-list of acceptable
commitment hash algorithms and MUST NOT accept algorithm substitution based
solely on attacker-controlled inputs.

## Commitment Function

Committed profiles use `actor_chain_commitment` to bind each accepted hop to the
prior accepted state. The commitment hash algorithm is selected once for the
workflow by the issuing Authorization Server during bootstrap and remains fixed
for the lifetime of that workflow instance.

Each `actor_chain_commitment` value is a signed commitment object whose payload
contains:

* `ctx`: the context string `actor-chain-commitment-v1`;
* `sid`: the workflow identifier;
* `acp`: the active profile identifier;
* `halg`: the hash algorithm identifier;
* `prev`: the prior commitment digest, or the bootstrap `initial_chain_seed` at
  workflow start;
* `step_hash`: `Hash_halg(step_proof_bytes)`; and
* `curr`: `Hash_halg(CanonicalEncode({ctx, sid, acp, halg, prev, step_hash}))`.

The `halg` value MUST be a text string naming a hash algorithm from the IANA
Named Information Hash Algorithm Registry {{IANA.Hash.Algorithms}}. This
specification permits only `sha-256` and `sha-384` for
`actor_chain_commitment`. Hash algorithms with truncated outputs, including
truncated `sha-256` variants, MUST NOT be used. Other registry values MUST NOT
be used with this specification unless a future Standards Track specification
updates this document.

When a profile-defined proof input refers to a prior
`actor_chain_commitment`, the value incorporated into the proof input MUST be
that prior commitment's verified `curr` digest, not the raw serialized
commitment object.

The abstract function used throughout this document is therefore:

~~~ text
Commit_AS(prev_digest, step_proof_bytes, halg)
  = AS-signed commitment object over payload {
      ctx,
      sid,
      acp,
      halg,
      prev = prev_digest,
      step_hash = Hash_halg(step_proof_bytes),
      curr = Hash_halg(CanonicalEncode({ctx, sid, acp, halg, prev, step_hash}))
    }
~~~

The exact wire encoding of the signed commitment object is defined in the JWT
and CWT bindings in Appendix A and Appendix B.

# Authorization Server Metadata

An Authorization Server supporting this specification SHOULD publish metadata
describing supported actor-chain capabilities.

This specification defines the following Authorization Server metadata values:

* `actor_chain_profiles_supported`:
  array of supported actor-chain profile identifiers. Each value MUST be the
  exact identifier string used both as the `actor_chain_profile` token request
  parameter value and as the `acp` claim value;
* `actor_chain_commitment_hashes_supported`:
  array of supported commitment hash algorithm identifiers;
* `actor_chain_receiver_ack_supported`:
  boolean indicating whether the Authorization Server supports processing and
  policy for `hop_ack`; and
* `actor_chain_refresh_supported`:
  boolean indicating whether the Authorization Server supports Refresh-Exchange
  processing under this specification.

If omitted, clients MUST NOT assume support for any actor-chain profile beyond
out-of-band agreement.

# Cross-Domain Re-Issuance

If the next hop does not trust the current Authorization Server directly, the
current actor MUST perform a second token exchange at the next domain's
Authorization Server.

The cross-domain Authorization Server MUST:

* validate the inbound token signature and issuer trust according to local
  policy;
* validate the selected actor-chain profile;
* validate the preserved chain-state structure;
* preserve `acp`;
* preserve `sid`;
* preserve `actor_chain`, if present;
* preserve `actor_chain_commitment`, if present, exactly as verified;
* continue to represent the same current actor; and
* NOT append the next recipient.

The cross-domain Authorization Server MAY mint a new local `jti`, apply a new
local expiry, change token format or envelope, and add local trust or policy
claims. It MUST NOT alter the verified preserved chain state.

# Refresh-Exchange

A current actor MAY use token exchange to refresh a short-lived transport token
without appending the actor chain or regenerating a step proof.

A Refresh-Exchange request MUST include:

* `actor_chain_refresh=true`;
* the current inbound actor-chain token as the RFC 8693 `subject_token`; and
* the same authenticated current actor that is represented by that token.

A Refresh-Exchange request MUST NOT broaden the active profile, represented
actor identity, readable chain state, committed chain state, or target context.
The requested target context MUST be identical to, or narrower than, the target
context already represented by the inbound token according to local policy.

When processing Refresh-Exchange, the Authorization Server MUST:

* validate the inbound token and the identity of the current actor;
* verify sender constraint and intended-recipient semantics as applicable;
* verify that the request does not append the chain, alter preserved chain
  state, or broaden target context; and
* issue a replacement token with a new `jti` and refreshed `exp`.

For Refresh-Exchange, the Authorization Server MUST preserve `sid`, `acp`,
`actor_chain`, and `actor_chain_commitment`, if present. A new step proof MUST
NOT be required, and a new commitment object MUST NOT be created.

A Refresh-Exchange MAY rotate the sender-constrained presentation key only if
the actor provides a key-transition proof that binds the new presentation key
to the same `sid` and ActorID under local policy, and the Authorization Server
verifies and records that proof. Such proof MAY be satisfied by continuity
mechanisms provided by the sender-constrained binding in use or by another
locally trusted proof-of-possession transition method. Otherwise, the sender-
constrained key binding MUST be preserved. Historical step proofs remain bound
to the keys used when those proofs were created and MUST be verified against
those historical bindings, not against a later rotated key.

A recipient or coordinating component MUST treat a token obtained by
Refresh-Exchange as representing the same accepted chain state as the inbound
token from which it was refreshed. If a sender-constrained key transition
occurred, recipients still validate historical step proofs against the keys
bound when those proofs were produced and rely on Authorization-Server records
or other retained evidence for the key-transition event itself.

# Error Handling

Token exchange errors in this specification build on OAuth 2.0 and OAuth 2.0
Token Exchange.

An Authorization Server processing a token exchange request:

* MUST return `invalid_request` for malformed or missing profile-defined
  parameters, malformed bootstrap context, malformed ActorID values, malformed
  commitment objects, or unsupported profile bindings;
* MUST return `invalid_target` when the requested audience, target context, or
  recipient is not permitted or not supported; and
* SHOULD return `invalid_grant` when the `subject_token` fails validation,
  sender-constrained verification fails, the intended-recipient check fails,
  continuity fails at token exchange, replay or freshness checks fail,
  `actor_chain_step_proof` verification fails, or the submitted prior state is
  inconsistent with the claimed profile state.

Recipients and Authorization Servers MUST return protocol-appropriate error
signals for authentication, authorization, profile-validation, and continuity
failures.

In HTTP deployments, this typically maps to 400-series status codes and OAuth-
appropriate error values. In non-HTTP deployments, functionally equivalent
protocol-native error signaling MUST be used.

Error responses and logs MUST NOT disclose undisclosed prior actors, full step
proofs, request-context digests, or other sensitive proof material unless the
deployment explicitly requires such disclosure for diagnostics.

# Common Validation Procedures

## Recipient Validation of an Inbound Token

Unless a profile states otherwise, a recipient validating an inbound actor-chain
token MUST verify:

* token signature;
* issuer trust;
* audience and target-context consistency according to local policy;
* expiry;
* sender constraint; and
* replay and freshness state.

## Authorization Server Validation of Token Exchange

Unless a profile states otherwise, an Authorization Server processing a token
exchange under this specification MUST verify:

* the inbound `subject_token`;
* the identity of the current actor;
* replay and freshness constraints;
* intended-recipient semantics for the inbound token; and
* authorization to act for the requested target context.

## Current-Actor Validation of a Returned Token

Unless a profile states otherwise, a current actor validating a returned token
from token exchange MUST verify the token signature, profile identifier, and
any profile-specific append-only or commitment checks before presenting that
token to the next hop.

# Asserted Delegation Path Profile

## Profile Identifier

The profile value for this profile is:

* `actor_chain_profile=asserted-delegation-path`
* `acp=asserted-delegation-path`

## Objective

The Asserted Delegation Path profile extends token exchange by carrying a
readable `actor_chain` and requiring chain-continuity validation by both the
current actor and the issuing Authorization Server at each hop.

## Security Model

This profile provides hop-by-hop readable chain integrity based on issuer-asserted chain state and continuity checks.

This profile assumes that an actor does not collude with its home Authorization
Server.

## Bootstrap

At workflow start, actor `A` MUST request a token from `AS1` with:

* `actor_chain_profile=asserted-delegation-path`
* `audience=B`

If `AS1` accepts the request, `AS1` MUST issue `T_A` containing at least:

* `acp=asserted-delegation-path`
* `actor_chain=[A]`
* `sid`
* `jti`
* `aud=B`
* `exp`

## Hop Processing

When `A` calls `B`, `A` MUST present `T_A` to `B`.

`B` MUST perform recipient validation as described in
"Recipient Validation of an Inbound Token".

`B` MUST extract the verified `actor_chain`.

`B` MUST verify that the last actor in `T_A.actor_chain` is `A`.

If that continuity check fails, `B` MUST reject the request.

## Token Exchange

To call `C`, `B` MUST submit `T_A` to `AS1` as the RFC 8693 `subject_token`.

`AS1` MUST perform token-exchange validation as described in
"Authorization Server Validation of Token Exchange".

`AS1` MUST read the prior chain from `T_A` and append `B`.

If the prior chain is `[A]`, the new chain is `[A,B]`.

`AS1` MUST issue `T_B` containing at least:

* `acp=asserted-delegation-path`
* `actor_chain=[A,B]`
* `sid`
* `jti`
* `aud=C`
* `exp`

## Returned Token Validation

Upon receipt of `T_B`, `B` MUST perform current-actor returned-token
validation as described in "Current-Actor Validation of a Returned Token".

`B` MUST verify that `T_B.actor_chain` is exactly the previously verified chain
from `T_A` with `B` appended.

If that append-only check fails, `B` MUST reject `T_B`.

## Next-Hop Validation

Upon receipt of the final B-token, `C` MUST perform recipient validation as
described in "Recipient Validation of an Inbound Token".

`C` MUST extract the verified `actor_chain`.

`C` MUST use the verified `actor_chain` for authorization decisions.

## Security Result

Under the non-collusion assumption, prior actors MUST NOT be silently inserted,
removed, reordered, or altered during token exchange.

## Limits

This profile does not address tampering by a colluding actor and its home
Authorization Server.

This profile does not by itself address malicious application payloads.

This profile does not by itself prevent confused-deputy behavior.

# Committed Delegation Path Profile

## Profile Identifier

The profile value for this profile is:

* `actor_chain_profile=committed-delegation-path`
* `acp=committed-delegation-path`

## Objective

The Committed Delegation Path profile builds on the Asserted Delegation Path
profile by adding per-hop actor-signed step proofs and cumulative committed
state, while preserving a readable `actor_chain` for downstream authorization.

## Security Model

This profile preserves readable chain-based authorization and provides stronger
accountability and non-repudiation than the Asserted Delegation Path profile.

This profile does not guarantee inline prevention of every invalid token that
could be issued by a colluding actor and its home Authorization Server.

The evidentiary value of this profile depends on retention or discoverability of
step proofs, exchange records, and associated verification material.

## Bootstrap

### Bootstrap Context Request

At workflow start, actor `A` MUST request bootstrap context from `AS1` with:

* `actor_chain_profile=committed-delegation-path`
* `audience=B`

`AS1` selects `halg` for the workflow according to local policy and the
supported values advertised in Authorization Server metadata.

`AS1` MUST generate:

* `sid`;
* `halg`; and
* `initial_chain_seed`.

The `halg` value in the bootstrap context MUST be either `sha-256` or
`sha-384` and MUST remain fixed for the lifetime of the workflow instance.

`initial_chain_seed` MUST be derived as:

* `Hash_halg("actor-chain-readable-committed-init" || sid)`

`AS1` MUST return bootstrap context containing at least:

* `sid`;
* `halg`;
* `initial_chain_seed`;
* `audience=B`; and
* a short expiry.

The bootstrap context MUST be integrity protected by `AS1` and MUST be single
use.

### Initial Actor Step Proof

`A` MUST construct:

* `actor_chain=[A]`

`A` MUST compute a step proof:

* `chain_sig_A = Sign_A("actor-chain-readable-committed-step-sig-v1" || sid || initial_chain_seed || [A] || target_context=TC_B)`

using canonical encoding.

`A` MUST submit a token request containing:

* `actor_chain_profile=committed-delegation-path`;
* `actor_chain_step_proof=chain_sig_A`; and
* the `AS1` bootstrap context.

### Bootstrap Issuance

`AS1` MUST verify:

* the bootstrap context;
* the identity of `A`; and
* the validity of `chain_sig_A`.

If verification succeeds, `AS1` MUST compute:

* `actor_chain_commitment = Commit_AS1(initial_chain_seed, chain_sig_A)`

`AS1` MUST then issue `T_A` containing at least:

* `acp=committed-delegation-path`
* `actor_chain=[A]`
* `actor_chain_commitment`
* `sid`
* `jti`
* `aud=B`
* `exp`

## Hop Processing

When `A` calls `B`, `A` MUST present `T_A` to `B`.

`B` MUST verify:

* token signature;
* issuer trust;
* audience;
* expiry;
* sender constraint; and
* replay and freshness state.

`B` MUST extract:

* `actor_chain`;
* `actor_chain_commitment`; and
* `sid`.

`B` MUST verify that the last actor in the readable chain is `A`.

If that continuity check fails, `B` MUST reject the request.

## Token Exchange

To call `C`, `B` MUST:

* construct `new_actor_chain=[A,B]`; and
* set `prior_commitment_digest` to the verified `curr` value extracted from `T_A.actor_chain_commitment`.

`B` MUST compute:

* `chain_sig_B = Sign_B("actor-chain-readable-committed-step-sig-v1" || sid || prior_commitment_digest || [A,B] || target_context=TC_C)`

using canonical encoding.

`B` MUST submit to `AS1`:

* `T_A` as the RFC 8693 `subject_token`; and
* `actor_chain_step_proof=chain_sig_B`.

`AS1` MUST verify:

* `T_A`;
* the identity of `B`;
* replay and freshness constraints;
* that `B` was an intended recipient of the inbound `subject_token`;
* that `B` is authorized to act for the requested target context; and
* that `chain_sig_B` binds:
  * the same `sid`;
  * the same prior commitment;
  * the reconstructed `new_actor_chain`; and
  * the requested target context `TC_C`.

If verification succeeds, `AS1` MUST compute:

* `actor_chain_commitment = Commit_AS1(prior_commitment_digest, chain_sig_B)`

`AS1` MUST issue `T_B` containing at least:

* `acp=committed-delegation-path`
* `actor_chain=[A,B]`
* `actor_chain_commitment`
* `sid`
* `jti`
* `aud=C`
* `exp`

## Returned Token Validation

Upon receipt of `T_B`, `B` MUST verify the token signature and profile fields.

`B` MUST verify that:

* the returned readable chain is exactly `[A,B]`; and
* the returned `actor_chain_commitment` equals
  `Commit_AS1(prior_commitment_digest, chain_sig_B)`.

If either check fails, `B` MUST reject `T_B`.

## Next-Hop Validation

Upon receipt of the final B-token, `C` MUST verify:

* issuer trust;
* token signature;
* audience;
* expiry;
* sender constraint; and
* replay and freshness state.

`C` MUST extract:

* `actor_chain`;
* `actor_chain_commitment`; and
* `sid`.

`C` MUST use the readable `actor_chain` for authorization decisions.

## Attack Handling

A claim that actor `V` participated in the chain MUST fail unless a valid step
proof for `V` can be produced and verified against the corresponding prior
committed state and `sid`.

If an actor is omitted from a later readable chain, that omitted actor MAY prove
prior participation by presenting:

* an earlier token showing the prior chain state; and
* the corresponding committed state and verifiable step proof, or an immutable
  Authorization-Server exchange record.

A denial of participation by actor `X` MUST fail if a valid step proof for `X`
is available and verifies.

## Security Result

This profile preserves readable chain-based authorization while making tampering
materially easier to detect, prove, and audit.

## Limits

This profile does not by itself solve malicious application payloads.

This profile does not by itself solve confused-deputy behavior.

This profile does not by itself solve privacy minimization or workflow
branching.

# Commitment-Only Delegation Path Profile

## Profile Identifier

The profile value for this profile is:

* `actor_chain_profile=commitment-only-delegation-path`
* `acp=commitment-only-delegation-path`

## Objective

The Commitment-Only Delegation Path profile builds on the Committed Delegation
Path profile by omitting the readable `actor_chain` from ordinary tokens and
retaining only cumulative committed state.

## Security Model

This profile minimizes prior-actor disclosure in ordinary tokens.

This profile preserves sender-constrained current-actor continuity and
cumulative committed state, but ordinary recipients see only an opaque
commitment object and not a readable prior-actor path.

This profile does not preserve readable prior-actor authorization at downstream
hops. Prior-actor integrity is ordinarily verifiable only by the issuing
Authorization Server or an auditor with access to retained step proofs or
exchange records.

This profile does not guarantee inline prevention of every invalid token that
could be issued by a colluding actor and its home Authorization Server.

The evidentiary value of this profile depends on retention or discoverability of
step proofs, exchange records, and associated verification material.

## Bootstrap

### Bootstrap Context Request

At workflow start, actor `A` MUST request bootstrap context from `AS1` with:

* `actor_chain_profile=commitment-only-delegation-path`
* `audience=B`

`AS1` selects `halg` for the workflow according to local policy and the
supported values advertised in Authorization Server metadata.

`AS1` MUST generate:

* `sid`;
* `halg`; and
* `initial_chain_seed`.

The `halg` value in the bootstrap context MUST be either `sha-256` or
`sha-384` and MUST remain fixed for the lifetime of the workflow instance.

`initial_chain_seed` MUST be derived as:

* `Hash_halg("actor-chain-private-committed-init" || sid)`

`AS1` MUST return bootstrap context containing at least:

* `sid`;
* `halg`;
* `initial_chain_seed`;
* `audience=B`; and
* a short expiry.

The bootstrap context MUST be integrity protected by `AS1` and MUST be single
use.

### Initial Actor Step Proof

`A` MUST compute:

* `chain_sig_A = Sign_A("actor-chain-private-committed-step-sig-v1" || sid || initial_chain_seed || actor=ActorID(A) || target_context=TC_B)`

using canonical encoding.

`A` MUST submit a token request containing:

* `actor_chain_profile=commitment-only-delegation-path`;
* `actor_chain_step_proof=chain_sig_A`; and
* the `AS1` bootstrap context.

### Bootstrap Issuance

`AS1` MUST verify:

* the bootstrap context;
* the identity of `A`; and
* the validity of `chain_sig_A`.

If verification succeeds, `AS1` MUST compute:

* `actor_chain_commitment = Commit_AS1(initial_chain_seed, chain_sig_A)`

`AS1` MUST then issue `T_A` containing at least:

* `acp=commitment-only-delegation-path`
* `actor_chain_commitment`
* `sid`
* `jti`
* `aud=B`
* `exp`

`T_A` MUST NOT contain a readable `actor_chain`.

## Hop Processing

When `A` calls `B`, `A` MUST present `T_A` to `B`.

`B` MUST verify:

* token signature;
* issuer trust;
* audience;
* expiry;
* sender constraint; and
* replay and freshness state.

`B` MUST extract:

* `actor_chain_commitment`; and
* `sid`.

`B` MUST verify that the token is being presented by `A`.

If that continuity check fails, `B` MUST reject the request.

## Token Exchange

To call `C`, `B` MUST set:

* `prior_commitment_digest` to the verified `curr` value extracted from `T_A.actor_chain_commitment`.

`B` MUST compute:

* `chain_sig_B = Sign_B("actor-chain-private-committed-step-sig-v1" || sid || prior_commitment_digest || actor=ActorID(B) || target_context=TC_C)`

using canonical encoding.

`B` MUST submit to `AS1`:

* `T_A` as the RFC 8693 `subject_token`; and
* `actor_chain_step_proof=chain_sig_B`.

`AS1` MUST verify:

* `T_A`;
* the identity of `B`;
* replay and freshness constraints;
* that `B` was an intended recipient of the inbound `subject_token`;
* that `B` is authorized to act for the requested target context; and
* that `chain_sig_B` binds:
  * the same `sid`;
  * the same prior commitment;
  * the identity of `B`; and
  * the requested target context `TC_C`.

If verification succeeds, `AS1` MUST compute:

* `actor_chain_commitment = Commit_AS1(prior_commitment_digest, chain_sig_B)`

`AS1` MUST issue `T_B` containing at least:

* `acp=commitment-only-delegation-path`
* `actor_chain_commitment`
* `sid`
* `jti`
* `aud=C`
* `exp`

`T_B` MUST NOT contain a readable `actor_chain`.

## Returned Token Validation

Upon receipt of `T_B`, `B` MUST verify the token signature and profile fields.

`B` MUST verify that the returned commitment equals:

* `Commit_AS1(prior_commitment_digest, chain_sig_B)`

If that check fails, `B` MUST reject `T_B`.

## Next-Hop Validation

Upon receipt of the final B-token, `C` MUST verify:

* issuer trust;
* token signature;
* audience;
* expiry;
* sender constraint; and
* replay and freshness state.

`C` MUST extract:

* `actor_chain_commitment`; and
* `sid`.

`C` MUST verify that the token is being presented by `B`.

`C` MUST use the verified presenting actor for authorization decisions.

`C` MUST NOT infer the identities or number of prior actors from
`actor_chain_commitment` alone. Inline verification at `C` establishes current-
actor continuity and preserved commitment continuity only; it does not by
itself reveal or validate the full prior delegation path.

## Attack Handling

A claim that actor `V` participated in the workflow MUST fail unless a valid
step proof for `V` can be produced and verified against the corresponding prior
committed state and `sid`.

If an actor is omitted from a later committed state, downstream recipients might
not detect that omission inline because readable prior-actor disclosure is
absent.

That omitted actor MAY prove prior participation by presenting:

* an earlier token showing the prior committed state; and
* the corresponding step proof or immutable Authorization-Server exchange
  record.

A denial of participation by actor `X` MUST fail if a valid step proof for `X`
is available and verifies against the corresponding prior committed state.

## Security Result

This profile reduces ordinary-token disclosure and token size while preserving
per-hop continuation proofs at the acting hop and cumulative committed state
across hops.

## Limits

This profile does not preserve readable prior-actor authorization at downstream
hops.

This profile does not by itself allow downstream hops to detect omission,
insertion, or reordering of prior actors inline once readable disclosure is
removed.

This profile does not hide prior actors from the Authorization Server that
processes token exchange.

This profile does not by itself solve malicious application payloads.

This profile does not by itself solve confused-deputy behavior.

This profile does not by itself solve workflow branching.

# Optional Receiver Acknowledgment Extension

A recipient MAY produce a receiver acknowledgment artifact, called `hop_ack`,
for an inbound actor-chain token. This OPTIONAL extension does not alter chain
progression semantics.

A valid `hop_ack` proves that the recipient accepted responsibility for the
identified hop, bound to the workflow identifier, prior chain state or prior
commitment state, presenting actor, recipient, target context, and request-
context digest.

`hop_ack` MUST NOT by itself append the recipient to the actor chain.

A recipient MUST NOT emit `hop_ack` with status `accepted` until it has either:

* completed the requested operation; or
* durably recorded sufficient state to recover, retry, or otherwise honor the
  accepted request according to local reliability policy.

A deployment MAY require `hop_ack` for selected hops, including terminal hops.
When `hop_ack` is required by policy, the calling actor and any coordinating
component MUST treat that hop as not accepted unless a valid `hop_ack` is
received and verified.

`hop_ack` does not by itself prove successful completion or correctness of the
requested operation.

Recipients are not required to issue `hop_ack` for rejected, malformed,
abusive, unauthorized, or rate-limited requests. Absence of `hop_ack` is
sufficient to prevent proof of acceptance.

The acknowledgment payload MUST include at least:

* `ctx` = `actor-chain-hop-ack-v1`;
* `sid`;
* `acp`;
* inbound token `jti`;
* presenting actor ActorID;
* recipient ActorID;
* `target_context`;
* `req_hash`; and
* `ack`, whose value MUST be `accepted`.

A `hop_ack` MUST be signed by the recipient using JWS or COSE, according to the
same token-format family used by the deployment. If a deployment cannot
construct a canonical request-context object for `req_hash`, it MUST use
`hop_ack` only when the inbound token is single-use for one protected request.

# Threat Model

This specification defines a multi-hop, multi-actor delegation model across one
or more trust domains. The security properties provided depend on the selected
profile, the correctness of sender-constrained token enforcement, the trust
relationship among participating Authorization Servers, and the availability of
step proofs or exchange records where relied upon.

## Assets

The protocol seeks to protect the following assets:

* continuity of the delegation path;
* integrity of prior-actor ordering and membership;
* continuity of the presenting actor;
* binding of each hop to the intended target;
* resistance to replay of previously accepted hop state;
* audit evidence for later investigation and proof; and
* minimization of prior-actor disclosure where privacy-preserving profiles are
  used.

## Adversaries

Relevant adversaries include:

* an external attacker that steals or replays a token;
* a malicious actor attempting to insert, omit, reorder, or repurpose hop
  state;
* a malicious actor colluding with its home Authorization Server;
* a malicious downstream recipient attempting to over-interpret or misuse an
  inbound token;
* an untrusted or compromised upstream Authorization Server in a multi-domain
  path; and
* an unsolicited victim service reached by a validly issued token without
  having agreed to participate.

## Assumptions

This specification assumes:

* verifiers can validate token signatures and issuer trust;
* sender-constrained enforcement is correctly implemented;
* the authenticated actor identity used in token exchange is bound to the actor
  identity represented in profile-defined proofs; and
* deployments that rely on later proof verification retain, or can discover,
  the verification material needed to validate archived step proofs and exchange
  records.

## Security Goals

The protocol aims to provide the following properties:

* in the Asserted Delegation Path profile, silent insertion, removal,
  reordering, or modification of prior actors is prevented under the assumption
  that an actor does not collude with its home Authorization Server;
* in the Committed Delegation Path profile, each accepted hop is additionally
  bound to an actor-signed step proof and cumulative committed state, improving
  detectability, provability, and non-repudiation; and
* in the Commitment-Only Delegation Path profile, ordinary tokens omit
  readable prior-actor state while preserving presenting-actor continuity and
  cumulative committed state for later verification.

## Non-Goals

This specification does not by itself provide:

* integrity or safety guarantees for application payload content;
* complete prevention of confused-deputy behavior;
* concealment of prior actors from the Authorization Server that processes
  token exchange;
* branching or fan-out semantics within a single linear workflow instance; or
* universal inline prevention of every invalid token that could be issued by a
  colluding actor and its home Authorization Server.

## Residual Risks

Even when all checks succeed, a valid token chain does not imply that the
requested downstream action is authorized by local business policy. Recipients
MUST evaluate authorization using the verified presenting actor, token subject,
intended target, and local policy.

Deployments that depend on independently verifiable provenance for high-risk
operations SHOULD require synchronous validation of committed proof state or
otherwise treat the issuing Authorization Server as the sole trust anchor.

# Security Considerations

## Sender-Constrained Enforcement is Foundational

The security of these profiles depends strongly on sender-constrained token
enforcement. If a token can be replayed by an attacker that is not the bound
actor, continuity checks become materially weaker.

## Canonicalization Errors Break Interoperability and Proof Validity

Any ambiguity in canonical serialization, actor identity representation, target
representation, or proof payload encoding can cause false verification failures
or inconsistent commitment values across implementations.

## Readable Chain Does Not Prevent Payload Abuse

A valid readable `actor_chain` does not imply that the application-layer request
content is safe, correct, or policy-conformant. Recipients MUST apply local
payload validation and authorization.

## Committed Profiles Depend on Proof Retention

The evidentiary benefits of the committed profiles depend on retention or
discoverability of step proofs, exchange records, and relevant verification
material. Without such retention, the profiles still provide structured
committed state, but post hoc provability and non-repudiation are materially
weakened.

## Commitment-Only Delegation Path Removes Inline Prior-Actor Visibility

Recipients using the Commitment-Only Delegation Path profile can validate the
presenting actor and preserved commitment continuity, but cannot authorize based
on readable prior-actor membership or order from the ordinary token alone.

## Cross-Domain Re-Issuance Must Preserve Chain State

A cross-domain Authorization Server that re-issues a local token for the next
recipient MUST preserve the relevant chain state unchanged. Any such
re-issuance MUST continue to represent the current actor and MUST NOT append the
recipient.

## Intended Recipient Checks Reduce Confused-Deputy Risk

Accepting Authorization Servers MUST ensure that the authenticated current actor
was an intended recipient of the inbound `subject_token`. This reduces a class
of deputy and repurposing attacks, though it does not eliminate all
confused-deputy scenarios.

## Chain Depth

Authorization Servers SHOULD enforce a configurable maximum chain depth. A
RECOMMENDED default is 10 entries. Relying Parties MAY enforce stricter limits.

## Key Management

Actors SHOULD use short-lived keys and/or hardware-protected keys. Deployments
that require long-term auditability MUST retain, or make durably discoverable,
the historical verification material needed to validate archived step proofs and
receiver acknowledgments after key rotation.

# Privacy Considerations

Readable-chain profiles disclose prior actors to downstream recipients.
Deployments that do not require readable prior-actor authorization SHOULD
consider the Commitment-Only Delegation Path profile.

The stable workflow identifier `sid` correlates all accepted hops within one
workflow instance. Accordingly, `sid` MUST be opaque and MUST NOT encode actor
identity, profile selection, business semantics, or target meaning.

Even in the privacy-preserving profile, the Authorization Server processing
token exchange observes the authenticated current actor and retained chain-
related proofs. Accordingly, that profile reduces ordinary-token disclosure but
does not hide prior actors from the issuing Authorization Server.

Deployments concerned with minimization SHOULD consider:

* pairwise or pseudonymous actor identifiers;
* omission of auxiliary claims unless receiving policy depends on them; and
* future selective-disclosure companion profiles.

## Selective Disclosure

This specification does not define a selective-disclosure encoding for
`actor_chain`. JWT-based selective disclosure, where used, MUST follow SD-JWT
{{!RFC9901}}. CWT-based selective disclosure, where used, MUST follow SD-CWT
{{!I-D.ietf-spice-sd-cwt}} or its successor.

This specification defines only the actor-chain-specific constraints on such
use:

* selective disclosure MUST preserve actor-chain order semantics;
* step proofs, receiver acknowledgments, and chain commitments are computed from
  the full issued values, not from a later disclosed subset; and
* a verifier MUST treat undisclosed information as unavailable and MUST require
  disclosure of any information needed for authorization.

# Audit and Logging Considerations

Authorization Servers supporting these profiles SHOULD retain records keyed by
`sid` and `jti`.

For committed profiles, such records SHOULD include:

* prior token reference;
* authenticated actor identity;
* step proof reference or value;
* issued token reference;
* committed chain state;
* requested audience or target context; and
* timestamps.

Actors SHOULD also retain local records sufficient to support replay detection,
incident investigation, and later proof of participation.

# Appendix A. JWT Binding (Normative)

This appendix defines the JWT and JWS wire representation for profile-defined
ActorID values, step proofs, receiver acknowledgments, and commitment
objects.

## ActorID in JWT

An ActorID is a JSON object with exactly two members:

* `iss`: a string containing the issuer identifier; and
* `sub`: a string containing the subject identifier.

The object MUST be serialized using JCS {{!RFC8785}} whenever it is included in
profile-defined proof or commitment inputs.

The `actor_chain` claim, when present in a JWT, is a JSON array of ActorID
objects.

## Step Proof in JWT

The `actor_chain_step_proof` token request parameter value MUST be a compact JWS
string. The JWS protected header MUST contain `typ=actc-step-proof+jwt`. The
JWS payload MUST be the UTF-8 encoding of a JCS-serialized JSON object.

For the Committed Delegation Path profile, the payload MUST contain:

* `ctx`;
* `sid`;
* `prev`;
* `target_context`; and
* `actor_chain`.

For the Commitment-Only Delegation Path profile, the payload MUST contain:

* `ctx`;
* `sid`;
* `prev`;
* `target_context`; and
* `actor`.

The `prev` member MUST be the base64url encoding of the prior commitment digest
or bootstrap seed bytes. The `actor_chain` member MUST be a JSON array of
ActorID objects. The `actor` member MUST be one ActorID object. The
`target_context` member MUST be either a JCS-serialized JSON string equal to
`aud` or a JCS-serialized JSON object that includes `aud` and any additional
target-selection members used by local policy. Before any proof input is hashed
or signed, `target_context` MUST be canonicalized using JCS exactly once;
verifiers MUST reproduce the same JCS bytes when validating the proof.

The JWS algorithm MUST be an asymmetric algorithm. The `none` algorithm MUST
NOT be used. The JWS verification key MUST be bound to the same ActorID as the
sender-constrained presentation key for the corresponding actor.

## Receiver Acknowledgment in JWT

A `hop_ack`, when used in a JWT deployment, MUST be a compact JWS string. The
JWS protected header MUST contain `typ=actc-hop-ack+jwt`. The JWS payload MUST
be the UTF-8 encoding of a JCS-serialized JSON object with at least these
members:

* `ctx`;
* `sid`;
* `acp`;
* `jti`;
* `target_context`;
* `req_hash`;
* `presenter`;
* `recipient`; and
* `ack`.

The `presenter` and `recipient` members MUST be ActorID objects. The `ack`
member MUST have the value `accepted`. The `target_context` member MUST follow
the same representation rules defined for step proofs. The `req_hash` member
MUST be the base64url encoding of a digest over the canonical request-context
object. The JWS signer MUST be the recipient, and the verification key MUST be
bound to the same recipient ActorID as any sender-constrained presentation key
used for the protected interaction.

## Commitment Object in JWT

The `actor_chain_commitment` claim value MUST be a compact JWS string. The JWS
protected header MUST contain `typ=actc-commitment+jwt`.

The JWS payload MUST be the UTF-8 encoding of a JCS-serialized JSON object with
exactly these members:

* `ctx`;
* `sid`;
* `acp`;
* `halg`;
* `prev`;
* `step_hash`; and
* `curr`.

The `halg` member MUST be either `sha-256` or `sha-384`. The members `prev`,
`step_hash`, and `curr` MUST be the base64url encodings of raw hash bytes.

The JWS payload signer MUST be the issuing Authorization Server. A verifier
MUST validate the JWS signature, verify that `halg` is locally permitted, then
validate that `curr` equals:

~~~ text
Hash_halg(JCS({ctx, sid, acp, halg, prev, step_hash}))
~~~

# Appendix B. CWT Binding (Normative)

This appendix defines the CWT and COSE wire representation for profile-defined
ActorID values, step proofs, receiver acknowledgments, and commitment
objects.

## ActorID in CWT

An ActorID is a deterministic CBOR map with exactly two integer-labeled
members:

* `1`: issuer identifier (`iss`); and
* `2`: subject identifier (`sub`).

The values for labels `1` and `2` MUST be CBOR text strings.

The `actor_chain` claim, when present in a CWT, is an array of such ActorID
maps.

## Step Proof in CWT

The `actor_chain_step_proof` token request parameter value MUST be the
base64url encoding of a COSE_Sign1 object {{!RFC9052}}.

The COSE_Sign1 payload MUST be a deterministic-CBOR-encoded map. Verifiers MUST
validate the exact `ctx` value and expected artifact-specific payload shape.

For the Committed Delegation Path profile, the payload map MUST contain:

* `1`: `ctx`;
* `2`: `sid`;
* `3`: `prev`;
* `4`: `target_context`; and
* `5`: `actor_chain`.

For the Commitment-Only Delegation Path profile, the payload map MUST
contain:

* `1`: `ctx`;
* `2`: `sid`;
* `3`: `prev`;
* `4`: `target_context`; and
* `6`: `actor`.

The value of `3` MUST be a byte string containing the prior commitment digest or
bootstrap seed bytes. The value of `5` MUST be an array of ActorID maps. The
value of `6` MUST be one ActorID map. The value of `4` MUST be either a CBOR
text string equal to `aud` or a deterministic-CBOR-encoded map that includes
`aud` and any additional target-selection members used by local policy. Before
any proof input is hashed or signed, `target_context` MUST be canonicalized
using deterministic CBOR exactly once; verifiers MUST reproduce the same bytes
when validating the proof.

The COSE algorithm MUST be asymmetric. Unprotected unauthenticated payloads MUST
NOT be used. The COSE verification key MUST be bound to the same ActorID as the
sender-constrained presentation key for the corresponding actor.

## Receiver Acknowledgment in CWT

A `hop_ack`, when used in a CWT deployment, MUST be the base64url encoding of a
COSE_Sign1 object {{!RFC9052}}. The COSE_Sign1 payload MUST be a
deterministic-CBOR-encoded map containing at least:

* `1`: `ctx`;
* `2`: `sid`;
* `3`: `acp`;
* `4`: `jti`;
* `5`: `target_context`;
* `6`: `req_hash`;
* `7`: `presenter`;
* `8`: `recipient`; and
* `9`: `ack`.

The values of `7` and `8` MUST be ActorID maps. The value of `9` MUST be the
text string `accepted`. The value of `5` MUST follow the same representation
rules defined for step proofs. The value of `6` MUST be a byte string
containing a digest over the canonical request-context object. The COSE signer
MUST be the recipient, and the verification key MUST be bound to the same
recipient ActorID as any sender-constrained presentation key used for the
protected interaction.

## Commitment Object in CWT

The `actor_chain_commitment` claim value MUST be a byte string containing a
COSE_Sign1 object.

The COSE_Sign1 payload MUST be a deterministic-CBOR-encoded map with exactly
these members:

* `1`: `ctx`;
* `2`: `sid`;
* `3`: `acp`;
* `4`: `halg`;
* `5`: `prev`;
* `6`: `step_hash`; and
* `7`: `curr`.

The value of `4` MUST be the text string `sha-256` or `sha-384`. The values of
`5`, `6`, and `7` MUST be byte strings containing raw hash bytes.

The payload signer MUST be the issuing Authorization Server. A verifier MUST
validate the COSE signature, verify that `halg` is locally permitted, then
validate that `curr` equals:

~~~ text
Hash_halg(Deterministic-CBOR({1:ctx, 2:sid, 3:acp, 4:halg, 5:prev, 6:step_hash}))
~~~

# Appendix C. Compact End-to-End Examples (Informative)

## Example 1: Asserted Delegation Path in One Domain

Assume `A`, `B`, and `C` are governed by `AS1`.

1. `A` requests a token for `B` under the Asserted Delegation Path profile.
2. `AS1` issues `T_A` with `actor_chain=[A]` and `aud=B`.
3. `A` calls `B` and presents `T_A`.
4. `B` validates `T_A`, verifies continuity, and exchanges `T_A` at `AS1` for
   a token to `C`.
5. `AS1` authenticates `B`, verifies that `B` was an intended recipient of the
   inbound token, appends `B`, and issues `T_B` with `actor_chain=[A,B]` and
   `aud=C`.
6. `B` validates that the returned chain is exactly the prior chain plus `B`.
7. `B` presents `T_B` to `C`.
8. `C` validates the token and authorizes based on the readable chain `[A,B]`.

## Example 2: Committed Delegation Path Across Two Domains

Assume `A` and `B` are governed by `AS1`, while `C` is governed by `AS2`.

1. `A` obtains bootstrap context from `AS1`, signs `chain_sig_A`, and receives
   `T_A` with `actor_chain=[A]` and `actor_chain_commitment`.
2. `A` calls `B` with `T_A`.
3. `B` validates `T_A`, constructs `[A,B]`, signs `chain_sig_B`, and exchanges
   `T_A` at `AS1` for a token to `C`.
4. `AS1` verifies `chain_sig_B`, updates the commitment, and issues `T_B` with
   `actor_chain=[A,B]` and `aud=C`.
5. Because `C` does not trust `AS1` directly, `B` performs a second exchange at
   `AS2`.
6. `AS2` preserves `acp`, `sid`, `actor_chain=[A,B]`, and
   `actor_chain_commitment`, and issues a local token trusted by `C` that still
   represents `B`.
7. `C` validates the local token, sees the readable chain `[A,B]`, and
   authorizes accordingly.

## Example 3: Commitment-Only Delegation Path

Assume `A`, `B`, and `C` use the Commitment-Only Delegation Path profile.

1. `A` obtains bootstrap context, signs `chain_sig_A`, and receives `T_A` with
   `actor_chain_commitment`, but no readable `actor_chain`.
2. `A` calls `B` with `T_A`.
3. `B` validates `T_A`, verifies that `A` is the presenter, signs
   `chain_sig_B`, and exchanges `T_A` at its home AS to obtain `T_B` for `C`.
4. `T_B` contains the updated `actor_chain_commitment`, but no readable chain.
5. `B` presents `T_B` to `C`.
6. `C` validates the token and authorizes based on the verified presenting actor
   `B` and local policy. `C` MUST NOT infer prior-actor identity or count from
   the commitment alone.

# Appendix D. Future Considerations (Informative)

## Terminal Recipient Handling

This specification defines special handling for the first actor in order to
initialize chain state. It does not define corresponding terminal-hop semantics
for a final recipient that performs work locally and does not extend the chain
further.

Future work MAY define:

* a terminal receipt proving that the recipient accepted the request;
* an execution attestation proving that the recipient executed a specific
  operation; and
* a result attestation binding an outcome or result digest to the final
  committed state.

## Receiver Acceptance and Unsolicited Victim Mitigation

This specification deliberately does not append a recipient merely because that
recipient was contacted. It also defines an OPTIONAL `hop_ack` extension that
lets a recipient prove accepted responsibility for a hop.

However, this specification still does not by itself prevent a malicious actor
from sending a validly issued token to an unsolicited victim service. Future
work MAY define stronger receiver-driven protections, including:

* stronger result attestations for completed terminal work;
* a challenge-response model for high-risk terminal hops; and
* recipient-issued nonces or capabilities that MUST be bound into the final
  accepted hop.

## Selective Disclosure

Future work MAY define companion profiles that selectively disclose actor-chain
information to specific recipients while retaining full committed state for
audit. Any such work should defer disclosure syntax, presentation mechanics,
and verifier processing to SD-JWT {{!RFC9901}} for JWT representations and to
SD-CWT {{!I-D.ietf-spice-sd-cwt}} for CWT representations, while defining only
the actor-chain-specific semantics needed by this specification.

## Branching and Fan-Out

This specification models a linear workflow. A future branching profile will
need to distinguish multiple valid successors from the same prior committed
state, rather than treating every additional successor as a replay or replay-
like state collision.

One possible approach is to introduce explicit branch identifiers and a tree-
structured commitment model in which parallel successors become sibling nodes
under a common root. Such a profile could support inclusion proofs, partial
disclosure, and more efficient branch verification than the linear base model,
while preserving a stable workflow root.

Those semantics are intentionally out of scope for this base specification.

## Evidence Discovery and Governance Interoperability

Committed profiles derive much of their value from later verification of step
proofs and exchange records. Future work MAY standardize interoperable evidence
discovery, retention, and verification-material publication.

Any such specification should define, at minimum, evidence object typing,
authorization and privacy controls for cross-domain retrieval, stable lookup
keys such as `jti` or `sid`, error handling, and retention expectations.

# Appendix E. Design Rationale and Relation to Other Work (Informative)

This document complements {{!RFC8693}} by defining chain-aware token-exchange
profiles. It also aligns with the broader SPICE architecture and companion
provenance work while remaining useful on its own.

This specification defines three profiles instead of one deployment mode so
that implementations can choose among readable chain-based authorization,
stronger committed-state accountability, and reduced ordinary-token disclosure
without changing the core progression model.

The base specification remains linear. Branching, richer selective disclosure,
and evidence-discovery protocols remain future work because they require
additional identifiers, validation rules, and interoperability work.

# Appendix F. Implementation Conformance Checklist (Informative)

An implementation is conformant only if it correctly implements the profile it
claims to support and all common requirements on which that profile depends.

At a minimum, implementers should verify that they have addressed the following:

* stable generation and preservation of `sid`;
* sender-constrained validation for every inbound token;
* exact ActorID equality over (`iss`, `sub`);
* canonical serialization for all proof and commitment inputs;
* intended-recipient validation during token exchange;
* replay and freshness handling for tokens and step proofs;
* exact append-only checks for readable-chain profiles;
* exact commitment verification for committed profiles;
* proof-key binding between ActorID, proof signer, and sender-constrained
  presentation key;
* non-broadening Refresh-Exchange processing, if supported;
* policy for when `hop_ack` is optional or required; and
* privacy-preserving handling of logs and error messages.

# IANA Considerations

This specification does not create a new hash-algorithm registry.
`actor_chain_commitment` uses hash algorithm names from the IANA Named
Information Hash Algorithm Registry {{IANA.Hash.Algorithms}}, subject to the
algorithm restrictions defined in this document.

## JSON Web Token Claims Registration

This document requests registration of the following claims in the "JSON Web
Token Claims" registry established by {{!RFC7519}}:

* **Claim Name**: `actor_chain`
* **Claim Description**: Ordered array of actor identity entries representing
  the delegation path.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Claim Name**: `actor_chain_commitment`
* **Claim Description**: Committed chain state binding accepted hop progression
  for the active profile.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Claim Name**: `acp`
* **Claim Description**: Actor-chain profile identifier for the issued token.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

## CBOR Web Token Claims Registration

This document requests registration of the following claims in the "CBOR Web
Token (CWT) Claims" registry established by {{!RFC8392}}:

* **Claim Name**: `actor_chain`
* **Claim Description**: Ordered array of actor identity entries representing
  the delegation path.
* **CBOR Key**: TBD
* **Claim Type**: array
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Claim Name**: `actor_chain_commitment`
* **Claim Description**: Committed chain state binding accepted hop progression
  for the active profile.
* **CBOR Key**: TBD
* **Claim Type**: bstr
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Claim Name**: `acp`
* **Claim Description**: Actor-chain profile identifier for the issued token.
* **CBOR Key**: TBD
* **Claim Type**: tstr
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]


## Media Type Registration

This document requests registration of the following media types in the
"Media Types" registry established by {{!RFC6838}}:

* **Media Type Name**: `application`
* **Media Subtype Name**: `actc-step-proof+jwt`
* **Required Parameters**: N/A
* **Optional Parameters**: N/A
* **Encoding Considerations**: binary
* **Security Considerations**: see [this document]
* **Interoperability Considerations**: N/A
* **Published Specification**: [this document]
* **Applications that use this media type**: OAuth 2.0 Token Exchange actor-chain step proofs
* **Fragment Identifier Considerations**: N/A
* **Additional Information**:
  * Magic Number(s): N/A
  * File Extension(s): N/A
  * Macintosh File Type Code(s): N/A
* **Person & email address to contact for further information**: IETF
* **Intended Usage**: COMMON
* **Restrictions on Usage**: N/A
* **Author**: IETF
* **Change Controller**: IETF

* **Media Type Name**: `application`
* **Media Subtype Name**: `actc-commitment+jwt`
* **Required Parameters**: N/A
* **Optional Parameters**: N/A
* **Encoding Considerations**: binary
* **Security Considerations**: see [this document]
* **Interoperability Considerations**: N/A
* **Published Specification**: [this document]
* **Applications that use this media type**: OAuth 2.0 Token Exchange actor-chain commitments
* **Fragment Identifier Considerations**: N/A
* **Additional Information**:
  * Magic Number(s): N/A
  * File Extension(s): N/A
  * Macintosh File Type Code(s): N/A
* **Person & email address to contact for further information**: IETF
* **Intended Usage**: COMMON
* **Restrictions on Usage**: N/A
* **Author**: IETF
* **Change Controller**: IETF

* **Media Type Name**: `application`
* **Media Subtype Name**: `actc-hop-ack+jwt`
* **Required Parameters**: N/A
* **Optional Parameters**: N/A
* **Encoding Considerations**: binary
* **Security Considerations**: see [this document]
* **Interoperability Considerations**: N/A
* **Published Specification**: [this document]
* **Applications that use this media type**: OAuth 2.0 Token Exchange actor-chain receiver acknowledgments
* **Fragment Identifier Considerations**: N/A
* **Additional Information**:
  * Magic Number(s): N/A
  * File Extension(s): N/A
  * Macintosh File Type Code(s): N/A
* **Person & email address to contact for further information**: IETF
* **Intended Usage**: COMMON
* **Restrictions on Usage**: N/A
* **Author**: IETF
* **Change Controller**: IETF

## OAuth Authorization Server Metadata Registration

This document requests registration of the following metadata names in the
"OAuth Authorization Server Metadata" registry established by {{!RFC8414}}:

* **Metadata Name**: `actor_chain_profiles_supported`
* **Metadata Description**: Supported actor-chain profile identifiers.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Metadata Name**: `actor_chain_commitment_hashes_supported`
* **Metadata Description**: Supported commitment hash algorithm identifiers.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Metadata Name**: `actor_chain_receiver_ack_supported`
* **Metadata Description**: Indicates support for receiver acknowledgments
  (`hop_ack`) under this specification.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Metadata Name**: `actor_chain_refresh_supported`
* **Metadata Description**: Indicates support for Refresh-Exchange under this
  specification.
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

## OAuth Parameter Registration

This document requests registration of the following parameter names in the
relevant OAuth parameter registry:

* **Parameter Name**: `actor_chain_profile`
* **Parameter Usage Location**: OAuth token endpoint request
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Parameter Name**: `actor_chain_step_proof`
* **Parameter Usage Location**: OAuth token endpoint request
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

* **Parameter Name**: `actor_chain_refresh`
* **Parameter Usage Location**: OAuth token endpoint request
* **Change Controller**: IETF
* **Specification Document(s)**: [this document]

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

<reference anchor="I-D.ietf-spice-sd-cwt" target="https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt">
  <front>
    <title>Selective Disclosure CBOR Web Tokens (SD-CWT)</title>
    <date month="January" day="13" year="2026"/>
  </front>
</reference>

<reference anchor="IANA.Hash.Algorithms" target="https://www.iana.org/assignments/named-information">
  <front>
    <title>Named Information Hash Algorithm Registry</title>
    <author fullname="IANA"/>
  </front>
</reference>

<reference anchor="RFC6838" target="https://www.rfc-editor.org/info/rfc6838">
  <front>
    <title>Media Type Specifications and Registration Procedures</title>
    <author initials="N." surname="Freed" fullname="Ned Freed"/>
    <author initials="J." surname="Klensin" fullname="John Klensin"/>
    <author initials="T." surname="Hansen" fullname="Tony Hansen"/>
    <date month="January" year="2013"/>
  </front>
  <seriesInfo name="BCP" value="13"/>
  <seriesInfo name="RFC" value="6838"/>
</reference>

<reference anchor="RFC6920" target="https://www.rfc-editor.org/info/rfc6920">
  <front>
    <title>Naming Things with Hashes</title>
    <author initials="S." surname="Farrell" fullname="Stephen Farrell"/>
    <author initials="D." surname="Kutscher" fullname="Dirk Kutscher"/>
    <author initials="C." surname="Dannewitz" fullname="Christian Dannewitz"/>
    <author initials="B." surname="Ohlman" fullname="Bengt Ohlman"/>
    <author initials="A." surname="Keranen" fullname="Ari Keranen"/>
    <author initials="P." surname="Hallam-Baker" fullname="Phill Hallam-Baker"/>
    <date month="April" year="2013"/>
  </front>
  <seriesInfo name="RFC" value="6920"/>
</reference>

<reference anchor="RFC2119" target="https://www.rfc-editor.org/info/rfc2119">
  <front>
    <title>Key words for use in RFCs to Indicate Requirement Levels</title>
    <author initials="S." surname="Bradner" fullname="Scott Bradner"/>
    <date month="March" year="1997"/>
  </front>
  <seriesInfo name="BCP" value="14"/>
  <seriesInfo name="RFC" value="2119"/>
</reference>

<reference anchor="RFC8174" target="https://www.rfc-editor.org/info/rfc8174">
  <front>
    <title>Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words</title>
    <author initials="B." surname="Leiba" fullname="Barry Leiba"/>
    <date month="May" year="2017"/>
  </front>
  <seriesInfo name="BCP" value="14"/>
  <seriesInfo name="RFC" value="8174"/>
</reference>

<reference anchor="RFC7515" target="https://www.rfc-editor.org/info/rfc7515">
  <front>
    <title>JSON Web Signature (JWS)</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="J." surname="Bradley" fullname="John Bradley"/>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura"/>
    <date month="May" year="2015"/>
  </front>
  <seriesInfo name="RFC" value="7515"/>
</reference>

<reference anchor="RFC7519" target="https://www.rfc-editor.org/info/rfc7519">
  <front>
    <title>JSON Web Token (JWT)</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="J." surname="Bradley" fullname="John Bradley"/>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura"/>
    <date month="May" year="2015"/>
  </front>
  <seriesInfo name="RFC" value="7519"/>
</reference>

<reference anchor="RFC8392" target="https://www.rfc-editor.org/info/rfc8392">
  <front>
    <title>CBOR Web Token (CWT)</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="E." surname="Wahlstroem" fullname="Erik Wahlstroem"/>
    <author initials="S." surname="Erdtman" fullname="Samuel Erdtman"/>
    <author initials="H." surname="Tschofenig" fullname="Hannes Tschofenig"/>
    <date month="May" year="2018"/>
  </front>
  <seriesInfo name="RFC" value="8392"/>
</reference>

<reference anchor="RFC8414" target="https://www.rfc-editor.org/info/rfc8414">
  <front>
    <title>OAuth 2.0 Authorization Server Metadata</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones"/>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura"/>
    <date month="June" year="2018"/>
  </front>
  <seriesInfo name="RFC" value="8414"/>
</reference>

<reference anchor="RFC8693" target="https://www.rfc-editor.org/info/rfc8693">
  <front>
    <title>OAuth 2.0 Token Exchange</title>
    <author initials="W." surname="Denniss" fullname="William Denniss"/>
    <author initials="J." surname="Bradley" fullname="John Bradley"/>
    <author initials="H." surname="Tschofenig" fullname="Hannes Tschofenig"/>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt"/>
    <date month="January" year="2020"/>
  </front>
  <seriesInfo name="RFC" value="8693"/>
</reference>

<reference anchor="RFC8785" target="https://www.rfc-editor.org/info/rfc8785">
  <front>
    <title>JSON Canonicalization Scheme (JCS)</title>
    <author initials="A." surname="Rundgren" fullname="Anders Rundgren"/>
    <date month="June" year="2020"/>
  </front>
  <seriesInfo name="RFC" value="8785"/>
</reference>

<reference anchor="RFC8949" target="https://www.rfc-editor.org/info/rfc8949">
  <front>
    <title>Concise Binary Object Representation (CBOR)</title>
    <author initials="C." surname="Bormann" fullname="Carsten Bormann"/>
    <author initials="P." surname="Hoffman" fullname="Paul Hoffman"/>
    <date month="December" year="2020"/>
  </front>
  <seriesInfo name="RFC" value="8949"/>
</reference>

<reference anchor="RFC9052" target="https://www.rfc-editor.org/info/rfc9052">
  <front>
    <title>CBOR Object Signing and Encryption (COSE): Structures and Process</title>
    <author initials="J." surname="Schaad" fullname="Jim Schaad"/>
    <date month="August" year="2022"/>
  </front>
  <seriesInfo name="RFC" value="9052"/>
</reference>

<reference anchor="RFC9334" target="https://www.rfc-editor.org/info/rfc9334">
  <front>
    <title>Remote ATtestation procedureS (RATS) Architecture</title>
    <author initials="H." surname="Birkholz" fullname="Henk Birkholz"/>
    <author initials="T." surname="Fossati" fullname="Thomas Fossati"/>
    <author initials="N." surname="Smith" fullname="Nancy Cam-Winget"/>
    <author initials="W." surname="Pan" fullname="Wei Pan"/>
    <author initials="C." surname="Tschofenig" fullname="Carsten Tschofenig"/>
    <date month="January" year="2023"/>
  </front>
  <seriesInfo name="RFC" value="9334"/>
</reference>

<reference anchor="RFC9901" target="https://www.rfc-editor.org/info/rfc9901">
  <front>
    <title>Selective Disclosure for JSON Web Tokens</title>
    <author initials="D." surname="Fett" fullname="Daniel Fett"/>
    <author initials="K." surname="Yasuda" fullname="Kristina Yasuda"/>
    <author initials="B." surname="Campbell" fullname="Brian Campbell"/>
    <date month="November" year="2025"/>
  </front>
  <seriesInfo name="RFC" value="9901"/>
</reference>
