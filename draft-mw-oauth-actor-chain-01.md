%%%
title = "Cryptographically Verifiable Actor Chains for OAuth 2.0 Token Exchange"
abbrev = "OAUTH-ACTOR-CHAIN"
category = "std"
docName = "draft-mw-oauth-actor-chain-01"
ipr = "trust200902"
area = "Security"
workgroup = "OAuth"
keyword = [
  "actor chain",
  "oauth",
  "rfc8693",
  "token exchange",
  "workload identity",
  "delegation",
  "AI agents",
  "MCP",
  "A2A"
]
date = 2026-06-15

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-oauth-actor-chain-01"
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
RFC6749 = {}
RFC8174 = {}
RFC7515 = {}
RFC7518 = {}
RFC7519 = {}
RFC8414 = {}
RFC8693 = {}
RFC8785 = {}
RFC6838 = {}
RFC6920 = {}

[informative]
RFC9334 = {}
RFC9901 = {}
RFC7662 = {}
RFC9421 = {}
RFC9449 = {}

[informative."I-D.ietf-spice-arch"]
  title = "Secure Patterns for Internet CrEdentials (SPICE) Architecture"
  [informative."I-D.ietf-spice-arch".target]
    href = "https://datatracker.ietf.org/doc/html/draft-ietf-spice-arch"

[informative."I-D.ietf-spice-s2s-protocol"]
  title = "SPICE Service to Service Authentication"
  [informative."I-D.ietf-spice-s2s-protocol".target]
    href = "https://datatracker.ietf.org/doc/html/draft-ietf-spice-s2s-protocol"

[informative."I-D.draft-mw-spice-intent-chain"]
  title = "Cryptographically Verifiable Intent Chain for AI Agent Content Provenance"
  [informative."I-D.draft-mw-spice-intent-chain".target]
    href = "https://datatracker.ietf.org/doc/html/draft-mw-spice-intent-chain"

[informative."I-D.draft-mw-spice-inference-chain"]
  title = "Cryptographically Verifiable Inference Chain for AI Agent Computational Provenance"
  [informative."I-D.draft-mw-spice-inference-chain".target]
    href = "https://datatracker.ietf.org/doc/html/draft-mw-spice-inference-chain"

[informative."I-D.draft-mw-spice-transitive-attestation"]
  title = "Transitive Attestation for Workload Proof of Residency"
  [informative."I-D.draft-mw-spice-transitive-attestation".target]
    href = "https://datatracker.ietf.org/doc/html/draft-mw-spice-transitive-attestation"

[informative."I-D.mw-oauth-tls-session-bound-tokens"]
  title = "TLS-Session-Bound Access Tokens for OAuth 2.0"
  [informative."I-D.mw-oauth-tls-session-bound-tokens".target]
    href = "https://datatracker.ietf.org/doc/html/draft-mw-oauth-tls-session-bound-tokens"

[informative."I-D.ietf-oauth-identity-chaining"]
  title = "OAuth Identity and Authorization Chaining Across Domains"
  [informative."I-D.ietf-oauth-identity-chaining".target]
    href = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining"
[normative."IANA.Hash.Algorithms"]
  title = "Named Information Hash Algorithm Registry"
  [normative."IANA.Hash.Algorithms".target]
    href = "https://www.iana.org/assignments/named-information"
%%%

.# Abstract

Multi-hop service-to-service and agentic workflows often exchange OAuth
access tokens across a sequence of actors. OAuth 2.0 Token Exchange permits
an `act` claim, including nested prior actors, but it does not define
interoperable rules for preserving, extending, disclosing, and validating a
delegation path across successive exchanges.

This document defines six actor-chain profiles for OAuth 2.0 Token Exchange:
Declared Full Disclosure, Declared Subset Disclosure, Declared Actor-Only
Disclosure, Verified Full Disclosure, Verified Subset Disclosure, and Verified
Actor-Only Disclosure. The profiles preserve the existing meanings of `sub`,
`act`, and `may_act`. They add explicit profile selection, a stable workflow
actor-chain identifier, profile-controlled actor disclosure, and, for verified
profiles, actor-signed step proofs with cumulative commitment state.

{mainmatter}

# Introduction {#introduction}

OAuth 2.0 Token Exchange [@RFC8693] is widely useful when one service,
workload, or agent receives a token and needs a new token to call another
service. In multi-hop workflows, however, each hop can lose standardized
continuity of the path by which the request arrived.

This specification defines an actor-chain profile family for OAuth 2.0 Token
Exchange with a deliberately narrow protocol surface. It standardizes how a
workflow actor-chain identifier is preserved, how actor progression is
appended or preserved across token exchanges, how much of that progression is
disclosed to each hop, and how verified profiles bind each accepted hop to
actor-signed evidence and
cumulative commitment state.

The core mechanism is intentionally narrow. A deployment selects one actor-chain
profile, preserves one workflow identifier, applies append-only or preserve-
state processing, discloses only the actor-chain information permitted by the
selected profile, and optionally uses actor-signed step proofs with cumulative
commitment state.

## Document Organization {#document-organization}

This document is organized into three labeled parts. The part labels are
organizational aids; the normative requirements are in the numbered sections
that follow.

Part I, "Overview and Scope", introduces the problem, the RFC 8693 gap, the
actor-chain model, the profile family, and the scope of this specification.

Part II, "Protocol Specification", defines the normative protocol requirements,
including terminology, conformance, profile selection, common processing,
validation, declared and verified profiles, preserve-state exchanges, receiver
acknowledgments, JWT/JWS binding, Security Considerations, Privacy Requirements
and Considerations, and IANA Considerations.

Part III, "Informative Rationale, Examples, and Operational Guidance", is
informative. It provides examples, deployment context, threat model, audit
guidance, design rationale, relationship to other work, wire examples, test
vectors, future considerations, out-of-scope use cases, and a detailed RFC 8693
comparison. It does not define conformance requirements. Where Part III
summarizes requirements from Part II, Part II controls. This material is
organized so that it could be separated into an Informational companion draft
in a future revision.

# Problem Statement {#problem-statement}

A common workflow path is:

~~~ text
A -> B -> C -> D
~~~

Actor `A` obtains a token for `B`. Later, `B` exchanges that token for a token
to call `C`. Then `C` may exchange again for `D`. Each exchange can be valid as
an OAuth token exchange, but the delegation path across the workflow is not, by
itself, standardized as an interoperable input to authorization policy and
audit.

Downstream recipients may need to know the full disclosed path, only an approved
subset, or only the immediate upstream actor. Some deployments also need later
proof that a specific actor participated in a specific hop. Without a profile,
implementations must invent local conventions for nested `act`, chain
continuity, disclosure control, and audit evidence.

# Standards Gap and Relationship to RFC 8693 {#standards-gap-rfc8693}

OAuth 2.0 Token Exchange [@RFC8693] defines the `act` claim for the
current actor. It also permits nested `act` values as a way to represent prior
actors. It does not define interoperable processing rules for constructing,
extending, preserving, disclosing, or validating an actor chain across a
sequence of token exchanges.

This specification preserves the existing RFC 8693 meanings of `sub`, `act`,
and `may_act`; those claim semantics are defined by [@RFC8693] and are not
redefined here.

This specification uses `actp` as an explicit actor-chain profile identifier.
When `actp` is present and identifies a profile defined here, this
specification defines additional processing rules for actor-chain workflow
continuity and profile-controlled disclosure.

When `actp` is absent, ordinary RFC 8693 semantics remain unchanged. Nested
prior `act` values, if present, remain governed by RFC 8693 and by the
specification or local policy applicable to that token.

This specification does not redefine RFC 8693 generally and it does not change
the behavior of plain RFC 8693 token-exchange outputs outside this profile
family.

# Solution Overview {#solution-overview}

This specification defines three explicit protocol signals around OAuth token
exchange:

* `actor_chain_profile`, a token request parameter selecting exactly one
  actor-chain profile;
* `actp`, a token claim carrying the selected profile identifier; and
* `acti`, a stable actor-chain identifier minted once at workflow start and
  preserved for the workflow instance.

A profiled access token may also carry `act`, using nested ActorID nodes as
the authoritative disclosed actor-chain fragment for that artifact. Verified
profiles additionally carry `actc`, a cumulative commitment object that links
the accepted hop to actor-signed step-proof evidence.

The declared profiles rely on the issuing Authorization Server to assert
actor-chain continuity and enforce disclosure policy. The verified profiles
add actor-signed step proofs and cumulative commitment state so that later
participants and auditors can validate stronger evidence of accepted hop
progression.

An optional receiver acknowledgment, `hop_ack`, lets a recipient provide signed
evidence that it accepted responsibility for a specific inbound hop without
appending itself to the actor chain.

# Actor-Chain Model {#actor-chain-model}

The actor chain advances only when an actor acts toward a later hop. Mere
receipt of a token does not append the recipient.

For example, if `A` calls `B`, and `B` later calls `C`, then `B` is appended
when `B` performs token exchange to act toward `C`. `C` is not appended merely
because it received the token. If `C` later acts toward `D`, then `C` is
appended at that later exchange.

The selected profile controls what profiled access tokens disclose.
Full-disclosure profiles disclose the complete actor chain for the hop.
Subset-disclosure profiles disclose an ordered subset or omit `act` entirely
according to Authorization Server policy. Actor-only profiles disclose only the
current actor. Verified profiles also carry cumulative commitment state for
stronger continuity evidence.

# Profile Summary {#profile-summary}

The six profiles are the cross-product of two evidence models and three
actor-chain disclosure modes.

The evidence model determines how chain continuity is established:

* Declared profiles rely on Authorization-Server-asserted chain continuity.
* Verified profiles add actor-signed step proofs and cumulative commitment
  state.

The disclosure mode determines how much actor-chain information is visible in
profiled access tokens:

* Full Disclosure exposes the complete actor chain for the hop.
* Subset Disclosure exposes an Authorization-Server-selected ordered subset,
  or omits `act`.
* Actor-Only Disclosure exposes only the current actor.

| Disclosure mode | Declared profile | Verified profile |
| --- | --- | --- |
| Full Disclosure | `declared-full` | `verified-full` |
| Subset Disclosure | `declared-subset` | `verified-subset` |
| Actor-Only Disclosure | `declared-actor-only` | `verified-actor-only` |

Deployments whose recipient authorization depends on prior-path membership or
actor order need a profile and disclosure policy that disclose the required
path evidence at that hop. Actor-only or omitted-`act` outcomes are not
sufficient for path-sensitive authorization decisions.

Selection of a profile is a deployment concern. Informative selection guidance,
including when an actor-chain profile is needed at all, how single-domain and
multi-domain deployments commonly map to the six profiles, and how action
sensitivity can affect that choice, appears in {{deployment-context}}.

# Scope and Non-Goals {#scope-non-goals}

This specification defines actor-chain profiles for OAuth 2.0 Token Exchange.
It standardizes profile selection, workflow identifier continuity, disclosed
actor-chain structure, profile-specific disclosure behavior, verified-profile
step proofs and commitment state, preserve-state exchanges, optional receiver
acknowledgments, metadata, error handling, and JWT/JWS bindings.

This document does not define:

* a replacement for OAuth 2.0 grant processing or RFC 8693 Token Exchange;
* a new actor-authentication, presenter-binding, token-binding, or transport
  security mechanism;
* a general call-graph language, branch merge semantics, or sibling-discovery
  protocol;
* application payload safety or business authorization policy;
* recipient-protected selective-disclosure mechanisms, such as encrypted,
  selectively revealable, or recipient-bound actor-chain presentations beyond
  the base disclosed `act` representation; or
* a cryptographic proof, inside preserved `actc` state, that a cross-domain
  `sub` value and a locally re-issued `sub` alias identify the same underlying
  subject.

Those topics remain local policy matters or candidates for companion
specifications.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@RFC2119] [@RFC8174]
when, and only when, they appear in all capitals, as shown here.

This document uses terminology from OAuth 2.0 Token Exchange
[@RFC8693]. Informative background material also refers to the SPICE
Architecture [@I-D.ietf-spice-arch] and the RATS Architecture [@RFC9334].

* **Actor**: A workload, service, application component, agent, or other
  authenticated entity that receives a token, performs work, and can
  subsequently act toward another actor.

* **Current actor**: The authenticated entity presently performing token
  exchange.

* **Authorization Server (AS)**: The OAuth 2.0 Authorization Server that issues
  tokens and validates token exchange requests under OAuth 2.0 and OAuth 2.0
  Token Exchange.

* **Disclosed current actor**: The actor identified by the outermost visible
  `act` node of an artifact when such a node is present. Depending on the
  selected profile and disclosure policy, the disclosed current actor MAY be
  the same as the operational current actor or MAY be absent from the returned
  profiled access token.

* **Presenting actor**: The actor that presents an inbound token to a
  recipient.

  Example: when `B` exchanges a token at the Authorization Server, `B` is the
  current actor. When `B` later presents the resulting token to `C`, `B` is the
  presenting actor.

  Unless otherwise qualified, references in this specification to the current
  actor are about the operational current actor performing exchange, not about
  whether that actor is disclosed inline in `act` for the next hop.

* **Recipient**: The actor or resource server identified as the intended target
  of an issued token.

* **Actor chain**: The ordered sequence of actors that have acted so far in one
  workflow instance.

* **Profiled access token**: The access token issued under this specification
  for presentation to the next hop. It is distinct from step proofs, bootstrap
  context handles, commitment objects, and receiver acknowledgments.

* **Disclosed actor chain**: The ordered actor sequence represented by the
  disclosed `act` structure in an artifact when `actp` is present. It is visible
  to any party that can read that artifact. In the base JWT/JWS binding, a
  returned profiled access token is visible to the current actor and to the
  next recipient. The outermost `act` identifies the disclosed current actor.
  Any nested `act` members identify prior disclosed actors only.

  The helper function `VisibleChain(act)` denotes the ordered ActorID sequence
  decoded from that disclosed `act` structure.

* **Actor-visible chain**: The exact ordered actor sequence that the current
  actor is permitted to know and extend for the next hop. In the verified
  profiles, this is the signed actor-visible chain carried in the step proof.
  It can be broader than the disclosed actor chain in the returned profiled
  access token under subset-disclosure or actor-only operation.

  Example: if `A` calls `B`, and `B` later exchanges the inbound token to
  call `C`, `B` might verify an inbound disclosed actor chain `[A]` and sign a
  verified-profile step proof over the actor-visible chain `[A,B]`. Under Full
  Disclosure, the returned profiled access token for `C` discloses `[A,B]`.
  Under Subset Disclosure, that returned token might disclose any
  policy-selected ordered subsequence of `[A,B]`, or omit `act` where
  allowed. Under Actor-Only Disclosure, that returned token discloses exactly `[B]`.

* **Authoritative workflow chain state**: Authorization-Server-retained state
  for the accepted workflow instance. It MAY be richer than the disclosed actor chain
  in any given issued token. It is used for continuity, branch
  correlation, forensic review, legal audit, and any policy-controlled future
  redisclosure. This specification does not require that such retained state be
  disclosed inline in profiled access tokens.

  In the full-disclosure profiles, the disclosed actor chain, the actor-visible
  chain, and the authoritative workflow chain state collapse to the same chain.
  They diverge only under subset and actor-only profiles, where the disclosed
  actor chain may be narrower than the actor-visible chain, which in turn may
  be narrower than the authoritative workflow chain state.

* **Proof-bound chain state**: The cumulative cryptographic state carried in
  `actc` that binds prior accepted chain state to a newly accepted hop.

* **Step proof**: A profile-defined proof signed by the current actor that
  binds that actor's participation to the workflow, prior accepted state, the
  profile-defined actor-visible chain for the hop, and target context.

* **Target context**: The canonical representation of the next-hop target that
  a profile-defined proof or acknowledgment binds to. It always includes the
  intended audience and MAY additionally include other target-selection inputs.
  If no such additional inputs are used, it is the single-member JSON object
  containing only `aud`.

* **Bootstrap context**: An opaque handle issued by the Authorization Server
  only to start a verified profile workflow. It lets the initial actor redeem
  bound bootstrap state at the token endpoint without carrying that state
  inline.

* **Actor-chain identifier (`acti`)**: A stable identifier minted once at workflow
  start and retained for the lifetime of the workflow instance.

* **Cross-domain re-issuance**: A second token exchange performed at another
  domain's Authorization Server in order to obtain a local token trusted by the
  next recipient, without extending the actor chain.

* **Home Authorization Server**: The Authorization Server at which the current
  actor normally performs the chain-extending token exchange for the next hop.
  In same-domain operation it is the issuer that validates prior chain state
  and issues the next profiled access token.

* **Continuity**: The property that the presenting actor of an inbound
  artifact is the same actor that the workflow state and any required disclosed
  current-actor information identify as the expected presenter.

* **Append-only processing**: The rule that a new actor is appended to the
  prior accepted workflow chain state, and to any disclosed actor chain
  fragment derived from it, without insertion, deletion, reordering, or
  modification of prior actors.

* **Terminal recipient**: A recipient that performs work locally and does not
  extend the actor chain further.

* **Refresh-Exchange**: A token-exchange operation by the same current actor
  that preserves accepted chain state while refreshing transport characteristics
  such as expiry according to local policy.

* **Local policy**: Deployment-specific authorization and risk rules used when
  this specification defers a decision to the Authorization Server or
  recipient. Local policy can include trust relationships, authenticated client
  identity, permitted audiences or resources, chain-depth limits, profile
  support, and business or risk controls.

# Conformance {#conformance}

An implementation MAY support one or more actor-chain profiles defined by this
specification. An implementation that claims support for a profile identified by
an `actp` value MUST implement the common requirements that apply to that
profile, the evidence-model requirements for that profile, the disclosure-mode
requirements for that profile, and any profile-specific deltas.

Authorization Servers, current actors, recipients, and libraries MUST apply the
rules associated with the explicit `actp` value. They MUST NOT infer another
profile from the apparent shape of `act`, from the presence or absence of
`actc`, or from local naming conventions.

An implementation that receives an unsupported `actp`, an unsupported required
artifact type, or a profile-required artifact that is absent, malformed, or
invalid MUST reject that artifact for profile processing. Implementations MAY
support opaque access-token deployments only when a companion validation
interface or out-of-band agreement exposes the information needed to satisfy the
selected profile's validation rules.

# Protocol Model {#protocol-model}

## Workflow Path Model

The basic workflow path model is:

~~~ text
A -> B -> C -> D
~~~

The first actor initializes the workflow. Each subsequent actor MAY:

1. validate an inbound token;
2. perform work; and
3. exchange that token for a new token representing itself toward the next hop.

## Workflow Progression

The actor chain advances only when an actor acts. Mere receipt of a token does
not append the recipient.

If `A` calls `B`, and `B` later calls `C`, then:

1. `A` begins the workflow and becomes the initial actor.
2. When `A` calls `B`, `B` validates a token representing `A`.
3. When `B` later exchanges that token to call `C`, `B` becomes the next
   actor.
4. `C` is not appended merely because `C` received a token. `C` is appended
   only if `C` later acts toward another hop.

Complete flow examples are provided in {{compact-examples}}.

# Relationship to RFC 8693 Claims {#rfc8693-claims}

This specification extends OAuth 2.0 Token Exchange [@RFC8693] without
changing the base meanings of `sub`, `act`, or `may_act`. It profiles
delegation-chain workflow continuity and profile-controlled disclosure across
token exchange hops.

When `actp` is absent, `act` has ordinary RFC 8693 semantics. Nested prior
`act` claims, if present, remain informational only for access-control
purposes, consistent with [@RFC8693].

The following rules apply when `actp` is present and points to a profile
defined by this specification:

* `sub` continues to identify the subject of the issued token.
* `acti` identifies the stable workflow instance for the accepted actor-chain
  state.
* If `act` is present, it is the authoritative disclosed actor-chain fragment
  for that artifact. The outermost `act`, when present, identifies the
  disclosed current actor. Each nested `act` member, when present, identifies
  the immediately prior disclosed actor.
* Reduced actor disclosure, including omission of prior actors, omission of the
  current actor from a disclosed subset, or omission of `act` entirely, does
  not turn a profiled access token into an ordinary impersonation output. When `actp`
  is present, the token remains a delegation-chain token under this
  specification.
* Plain RFC 8693 outputs that do not carry this specification's profile
  signals remain outside this profile family whether or not they contain
  `act`.

## Actor-Chain Disclosure Boundary {#actor-chain-disclosure-boundary}

For any selected `actp`, the Authorization Server is the policy decision and
policy enforcement point for actor-chain disclosure. The selected profile
defines the maximum actor-chain information, if any, that may be visible inline
to the next hop.

Accordingly:

* no other field, identifier encoding, compatibility form, or exchange option
  may disclose more actor-chain information than the selected profile permits;
* recipients and intermediaries MUST NOT infer hidden actors from omitted
  entries, identifier structure, or other claims; and
* when a profile hides prior actors or the workflow subject's globally useful
  identifier, the Authorization Server MUST enforce that outcome across the
  entire issued artifact, not only within `act`.

Nothing in this specification redefines RFC 8693 delegation or impersonation
semantics. With `actp` absent, this document adds no new requirements on how
nested `act` is interpreted. With `actp` present, this document defines an
explicit profile-controlled extension in which the disclosed `act` structure
becomes authoritative for actor-chain processing under that profile.

# Profile Selection and Workflow Immutability {#profile-selection}

This specification uses capability discovery plus explicit profile selection,
not interactive profile negotiation.

An actor requesting a token under this specification MUST select exactly one
`actor_chain_profile` value for that request. The Authorization Server MUST
either issue a token whose `actp` equals that requested profile identifier or
reject the request.

For a given workflow instance identified by `acti`, `actp` is immutable.
Accordingly, every accepted chain state within that workflow instance carries
the same `actp`. Any token exchange, cross-domain re-issuance, or
Refresh-Exchange that would change `actp` for that workflow instance MUST be
rejected. A current actor MUST reject any returned token whose `actp` differs
from the profile it requested or from the preserved profile state already
represented by the inbound token.

Profile switching therefore requires starting a new workflow instance with a
new `acti`, not continuing an existing accepted chain state.

# Common Workflow Processing {#common-workflow-processing}

The chain-extending profile flows have the same shape:

1. an initial actor starts a workflow under exactly one selected profile;
2. the issuing Authorization Server mints a stable `acti` and a workflow
   subject representation;
3. each recipient validates the inbound token before relying on it;
4. an actor that later acts toward another hop exchanges the inbound token for
   a successor token targeted to the next recipient;
5. the Authorization Server performs profile-specific continuity,
   disclosure, and replay or freshness checks; and
6. the returned profiled access token carries the same `acti`, the same
   `actp`, the preserved workflow subject, and the disclosed actor-chain state
   governed by the selected profile for the next hop.

A chain-extending exchange appends the authenticated current actor according to
the selected profile. Preserve-state exchanges, defined in
{{preserve-state-exchanges}}, do not append an actor.

# Common Token and Actor Identity Requirements {#token-actor-identity}

## Common Token Requirements {#common-token-requirements}

Unless stated otherwise, "profiled access token" below means the access token
issued to the current actor for presentation to the next hop.
This section is about those tokens, not about verified-profile step proofs,
bootstrap context handles, or `hop_ack` objects.

In the interoperable self-contained profiled access token binding defined by
this document, profiled access tokens issued under any profile:

* MUST be short-lived;
* MUST contain:
  * an issuer claim `iss`;
  * a profile identifier claim `actp`;
  * an actor-chain identifier claim `acti`;
  * a subject claim `sub`;
  * a unique token identifier claim `jti`;
  * an audience value `aud`; and
  * an expiry value `exp`.

A profiled access token MAY additionally contain `act` according to
the selected profile and Authorization Server policy.

For interoperability and predictable freshness, deployments SHOULD use
profiled access token lifetimes on the order of minutes rather than hours; a
default range of 1 to 10 minutes is RECOMMENDED. Validators SHOULD allow only
modest clock skew when evaluating `exp`, typically no more than 60 seconds unless
local clock discipline justifies a tighter bound.

Profiled access tokens issued under verified profiles MUST also carry `actc`.

The token claims used by this document have these roles:

* `iss` identifies the issuer namespace of the profiled access token and of that
  token's top-level `sub`;
* `actp` identifies the selected actor-chain profile;
* `acti` identifies the workflow instance;
* `sub` identifies the workflow subject of the token;
* `act`, when present, carries the authoritative disclosed actor-chain
  fragment for that artifact; and
* `actc`, when present, carries cumulative commitment state for stronger
  tamper evidence, continuity, and auditability.

This base specification defines interoperable direct claim carriage for
self-contained profiled access tokens. Deployments that instead use opaque access
tokens MAY keep authoritative workflow state only at the issuing Authorization
Server and MAY disclose actor-chain information, if any, through a companion
token-validation interface such as token introspection [@RFC7662].

This specification does not define such companion interfaces. If the artifact
presented for validation does not expose enough information to satisfy the
selected profile's requirements, the implementation MUST treat that as a
profile-validation failure.

Accordingly, interoperability requirements in this base specification apply to
the self-contained profiled access token claim carriage defined here. Opaque-token
deployments depend on companion validation interfaces outside this document and
therefore require either out-of-band agreement or a companion specification for
interoperable behavior.

At workflow bootstrap, the issuing Authorization Server MUST establish the
workflow subject according to local policy and the selected disclosure profile.
The resulting `sub` value MAY be an ordinary subject identifier, a pairwise
identifier, or a workflow-local stable alias. For privacy-sensitive
subset-disclosure operation, the Authorization Server SHOULD choose a stable
representation that does not reveal a globally useful subject identifier to
recipients that are not entitled to learn it.

For same-domain token exchange and Refresh-Exchange, this specification
preserves that exact chosen `sub` representation within the same domain for the
lifetime of the workflow unless a later permitted cross-domain alias transition
occurs. Cross-domain re-issuance MAY translate `sub` only under the
cross-domain subject-handling rules in {{cross-domain-subject}}. This document
does not define a same-workflow subject-transition mechanism.

The chosen `sub` representation for a workflow MUST remain consistent with the
selected `actp` disclosure constraints. In particular, `sub` MUST NOT disclose
an actor identity or other actor-chain information that the selected profile is
intended to withhold from the relevant recipient class.

In this self-contained JWT/JWS binding, a returned profiled access token is visible
to the current actor that receives it and to the next recipient that validates
it. Therefore, when a profile returns a disclosed `act`, the Authorization Server
MUST NOT disclose in that returned token any actor identity that the current
actor is not permitted to learn. A future recipient-protected disclosure
mechanism or encrypted binding may support stronger recipient-only
redisclosure, but that is outside this base specification.

## Actor-Chain Identifier {#actor-chain-identifier}

The `acti` value:

* MUST be minted once at workflow start by the issuing Authorization Server;
* MUST be generated using a cryptographically secure pseudorandom number
  generator (CSPRNG) with at least 122 bits of entropy;
* MUST remain unchanged for the lifetime of that workflow instance;
* MUST NOT be used to signal profile selection;
* MUST be unique within the issuing Authorization Server for at least the
  retention period required to validate any artifact that references that
  `acti`, including `actc`, step proofs, and `hop_ack`; and
* SHOULD be generated so that collision probability across issuing
  Authorization Servers is negligible, for example by using 128 bits of random
  entropy where practical.

Reuse of an `acti` value within its required retention period would make
commitment continuity, step-proof verification, and `hop_ack` correlation
ambiguous. An Authorization Server MUST NOT reuse an `acti` within that period.

Implementation note: standard UUID version 4 (UUIDv4), which provides 122 bits
of random entropy, is acceptable for `acti` in this version. Deployments MAY
use stronger generation, for example full 128-bit random values, by local
policy.

Profile selection MUST be signaled explicitly using the token request parameter
`actor_chain_profile` and the corresponding token claim
`actp`.

## Target Context Requirements {#target-context}

`target_context` is the canonical next-hop target value bound into verified
profile step proofs and, when used, into `hop_ack`.

In this base specification, `aud` identifies the intended recipient service or
audience of the issued token. An optional `resource` value can further identify
a narrower protected resource, API surface, or object within that audience.
When no finer-grained targeting inputs are used, the canonical target context is
still a JSON object that contains only `aud`.

The following normative requirements apply to `target_context`.

For every profile-defined signed, hashed, compared, retained, or communicated
use in this specification, `target_context` MUST be a JSON object.

`target_context` MUST contain an `aud` member carrying the verified audience
information exactly in the profile-defined canonical representation. If `aud` is
a string, `target_context.aud` MUST be that same JSON string. If `aud` is an
array of strings, `target_context.aud` MUST be that exact JSON array, preserving
element order.

A chain-extending profiled access token MUST identify exactly one logical
chain-extending recipient. `target_context.aud` SHOULD therefore be a string. An
array value MAY be used only when the array is defined by local policy or an
applicable profile as one indivisible composite audience and no individual
audience member can independently extend the actor chain from that token. If
multiple independently callable recipients are intended, the Authorization
Server MUST issue separate successor tokens, each with its own `jti` and
distinct canonical `target_context`. If a unique logical chain-extending
recipient cannot be determined, profile validation MUST fail.

If no additional target-selection values are used, `target_context` MUST be the
single-member object `{ "aud": aud }`.

A deployment MAY additionally include:

* `resource`, when the hop is bound to a narrower protected resource or API
  surface within the audience;
* `request_id`, when the deployment expects multiple distinct accepted
  successors under the same prior state and the same nominal target; and
* other local extension members used by same-domain local authorization policy.

Optional `target_context` members are optional only at construction time. Once a
profile-defined artifact is signed, hashed, compared, retained, or
communicated, the exact canonical `target_context` object carried in that
artifact is the value that is bound for verification. Verifiers MUST NOT add,
remove, infer, synthesize, or policy-fill omitted members during validation or
post-facto verification. A member omitted from the canonical object is not
cryptographically bound by that artifact.

This base specification assigns interoperable security semantics to `aud`,
optional `resource`, and optional `request_id`. Other `target_context` members
MAY be used within one domain by local policy. At a cross-domain boundary, a
member whose semantics are not understood under this specification, an
applicable Standards Track extension, a companion profile, or an explicit
bilateral semantic mapping is a non-droppable constraint: the re-issuing
Authorization Server MUST either preserve that member exactly with validation
behavior that continues to constrain the returned local token authority, or
reject the re-issuance. Unknown members MUST NOT be ignored, removed,
defaulted, or treated as non-security-relevant when determining equivalence or
narrowing.

When a deployment expects multiple distinct successors under the same prior
state and the same nominal target, it MUST include a request-unique
discriminator such as `request_id` inside `target_context`.

`target_context` members MUST NOT disclose actor identities or other actor-chain
information that the selected `actp` would withhold from the relevant holder of
the artifact.

An Authorization Server that validates, preserves, or audits workflow
continuity using `target_context` MUST retain the exact canonical
`target_context` value for the accepted hop, or retained request material from
which the identical canonical JSON object can be deterministically reproduced,
including the presence and absence of every member. Reconstruction MUST NOT rely
on later policy inference, default insertion, or semantic approximation.

Whenever `target_context` is incorporated into a profile-defined signature or
commitment input in this JWT-based version, it MUST be represented as a JSON
object and canonicalized exactly once as part of the enclosing JSON
Canonicalization Scheme (JCS)-serialized payload object. Equality checks over
`target_context` MUST therefore compare the exact JSON object value after JCS
canonicalization. Implementations MUST NOT collapse an audience array to a
string, replace an object with a bare `aud` value, reorder array elements, or
otherwise rewrite the verified audience structure before signing or comparing
`target_context`.

## Actor Identity Representation {#actor-identity}

This specification requires a canonical representation for actor identity in
profile-defined disclosed-chain entries and step proofs.

Each canonical actor identifier used by this specification MUST be
represented as an ActorID structure containing exactly two members:

* `iss`: the issuer identifier naming the namespace in which the actor subject
  value is defined; and
* `sub`: the subject identifier of the actor within that issuer namespace.

An ActorID is a JSON object with members `iss` and `sub`, serialized using
JCS [@RFC8785] when incorporated into profile-defined signed or hashed inputs.

An ActorID:

* MUST be stable for equality comparison within a workflow instance;
* MUST be bound to the actor identity accepted under local policy for the
  relevant exchange, proof-verification, or acknowledgment-validation step;
* MUST be compared using exact equality of the pair (`iss`, `sub`); and
* SHOULD support pairwise or pseudonymous subject values where deployment
  policy allows.

When deriving an ActorID from a validated inbound token:

* for the token subject, use `{ "iss": token.iss, "sub": token.sub }`;
* for a validated `act` claim that contains both `iss` and `sub`, use those two
  values directly; and
* for a validated `act` claim that contains `sub` but omits `iss`, use the
  enclosing token's `iss` as the ActorID `iss` value and the `act.sub` value as
  the ActorID `sub` value.

If no usable `act` claim is present and a profile needs the presenting actor,
that actor MUST be established from actor authentication or other locally
trusted inputs outside the scope of this specification and mapped into the same
ActorID representation the issuing Authorization Server uses for proof
construction.

When `actp` is present, the `act` structure used by this specification is an
ActorChainNode. An ActorChainNode is an ActorID object plus an OPTIONAL nested
member named `act` whose value is another ActorChainNode representing the
immediately prior disclosed actor. Newly issued profile-defined `act`
structures MUST carry explicit `iss` and `sub` in every disclosed node. Implementations
MUST be able to decode and normalize a validated inbound disclosed actor chain even
when a node omits `iss` and inherits the enclosing issuer according to the
derivation rule above.

The helper functions used throughout this document are therefore:

~~~ text
VisibleChain(act) = ordered list of ActorID values obtained by recursively
                    reading nested `act` from the innermost prior actor to the
                    outermost current actor.

EncodeVisibleChain([A]) = {"iss": A.iss, "sub": A.sub}
EncodeVisibleChain([A,B]) = {"iss": B.iss, "sub": B.sub, "act":
                             {"iss": A.iss, "sub": A.sub}}
EncodeVisibleChain([A,B,C]) = {"iss": C.iss, "sub": C.sub, "act":
                               {"iss": B.iss, "sub": B.sub, "act":
                                {"iss": A.iss, "sub": A.sub}}}
~~~

In examples and formulas, `[A,B]` denotes an ordered ActorID sequence for
actors `A` and `B`, while `EncodeVisibleChain([A,B])` denotes the nested JSON
representation carried in `act`.

## Issued Token Type {#issued-token-type}

Unless another application profile explicitly states otherwise, tokens issued
under this specification are access tokens.

Token exchange responses MUST use the RFC 8693 token type fields consistently
with the underlying representation and deployment.

# Common Validation Procedures {#common-validation}

This section gives the short validation checklists that the profile sections
reuse. Detailed enforcement rules for actor authentication inputs, proof-key
binding, intended-recipient handling, and replay or freshness are collected in
{{security-enforcement}}.

Implementations can think of validation in three layers:

* **Layer 1: Admission** -- JWT signature, issuer trust, expiry, audience,
  intended-recipient checks, and any locally established presenting-actor or
  current-actor continuity checks required for that processing step.
* **Layer 2: Profile authorization** -- interpretation of the disclosed nested
  `act` according to `actp` and application of local authorization policy using
  only the disclosed actor chain that the profile exposes.
* **Layer 3: Continuity and audit evidence** -- validation of `actc`, step
  proofs, acknowledgments, and retained Authorization Server records.

Recipients that only consume an inbound token MAY apply Layer 3 according to
local policy. Current actors that extend a verified workflow, and
Authorization Servers that accept verified profile token exchange, MUST
validate the inbound `actc` and any required step proof before extending the
workflow.

## Recipient Validation of an Inbound Token {#recipient-validation}

Unless a profile states otherwise, a recipient validating an inbound actor-chain
token MUST verify:

* token signature;
* issuer trust;
* profile identifier (`actp`);
* presence and correct format of profile-required structural claims (`actc`
  and any profile-required disclosed `act` according to `actp`);
* expiry and replay requirements;
* intended-recipient requirements; and
* any profile-specific disclosed-chain checks.

If a disclosed `act` is present, a recipient MUST decode the disclosed actor
chain as `VisibleChain(act)` and apply the profile-specific checks on that
disclosed actor chain. If the selected profile requires disclosed current-actor continuity and
the recipient establishes a presenting-actor identity for the inbound hop under
local policy, the recipient MUST also verify that the outermost `act` identifies
that same presenting actor. If the selected profile requires inline `act`
disclosure, omission of `act`, or presence of an `act` that violates the
profile's required disclosure rules, MUST be treated as a profile-validation
failure.

A recipient MUST use only the actor-chain information actually disclosed in the
inbound artifact for authorization. It MUST treat undisclosed prior actors, and
an undisclosed current actor, as unavailable from that artifact.

## Authorization Server Validation of Token Exchange {#as-token-exchange-validation}

Unless a profile states otherwise, an Authorization Server validating an
actor-chain token exchange MUST verify:

* the inbound token signature and issuer trust;
* the authenticated identity of the current actor;
* intended-recipient semantics for the inbound token;
* the selected profile identifier and any profile-specific step-proof
  requirements;
* the preserved `acti` and `sub` continuity expected for the workflow; and
* any profile-specific disclosed-chain checks on any inbound `act`.

If the inbound token contains disclosed actor-chain state, the Authorization
Server MUST decode `VisibleChain(act_in)` from the inbound token exactly as verified
for the current actor and MUST perform only append-only operations on that
disclosed actor chain fragment. If the selected profile requires disclosed
current-actor continuity, the Authorization Server MUST additionally verify
that the outermost `act` of the inbound token identifies the same actor that
authenticated as the current actor and is presenting that inbound hop for
exchange. If the selected profile requires inline `act` disclosure, omission of
`act`, or presence of an `act` that violates the profile's required disclosure
rules, MUST be treated as a profile-validation failure.

This specification does not define validation or handling rules for
`may_act`. Any effect of `may_act` is determined by RFC 8693, by the
specification governing the artifact that carries it, or by local policy. Such
use MUST NOT cause an artifact issued under this specification, or any related
protocol-visible outcome, to disclose actor-chain information that the
selected profile would withhold.

A token-exchange request under this specification MAY additionally carry the RFC
8693 `actor_token` and `actor_token_type` parameters. This specification does
not define whether or how `actor_token` contributes actor-related policy input.
Any such effect is determined by RFC 8693, by the specification governing that
artifact, or by local policy. Such use MUST NOT expand disclosure beyond the
selected profile and Authorization Server policy, and MUST NOT alter required
`acti`, `actp`, or `sub` continuity.

When `actor_token` is presented together with this specification's
verified-profile parameters, the Authorization Server MUST decide under local
policy which ActorID represents the current actor for that exchange. The
Authorization Server MUST reject the request with `invalid_grant` unless that
ActorID matches the ActorID represented in the submitted
`actor_chain_step_proof` and the proof-signing key is trusted for that ActorID
under local policy. The Authorization Server MUST NOT accept a step proof
attributed to one ActorID while appending a different ActorID to the accepted
actor-chain state.

If neither `may_act` nor `actor_token` contributes actor-related policy input,
the Authorization Server applies local policy. For this specification, local
policy can include trust relationships, authenticated client identity,
permitted target contexts, chain-depth limits, profile support, and business or
risk controls.

## Current-Actor Validation of a Returned Token {#returned-token-validation}

Unless a profile states otherwise, a current actor validating a returned token
MUST verify:

* token signature and issuer trust;
* that the returned `actp` equals the requested profile identifier and any
  preserved active profile state;
* that the returned `acti` equals the actor-chain identifier already represented by
  the inbound token or bootstrap state;
* that the returned `sub` equals the expected preserved workflow-subject value;
* expiry and replay requirements; and
* any profile-specific disclosed-chain or commitment checks.

If a returned token discloses `act`, the current actor MUST verify that the
disclosed `act` conforms to the selected profile and Authorization Server
policy for that hop. If the selected profile requires inline `act` disclosure,
omission of `act`, or presence of an `act` that violates the profile's
required disclosure rules, MUST be treated as a profile-validation failure.

For full-disclosure profiles, the current actor MUST verify that the
returned disclosed actor chain equals the complete chain expected for that
hop. For
subset-disclosure profiles, if the returned token discloses `act`, the current
actor MUST verify that the returned disclosed actor chain is an ordered subsequence of
the exact verified actor-visible chain that the actor signed or otherwise
caused to be asserted for that hop. For actor-only profiles, the current actor
MUST verify that the returned `act` consists only of the outermost current
actor and that this actor is the current actor that requested or caused the
hop.

# Profiles {#profiles}

This specification defines six explicit actor-chain profiles. For readability,
this section specifies them as the cross-product of two evidence models and
three disclosure modes:

~~~ text
Profile = EvidenceModel x DisclosureMode

EvidenceModel = declared | verified
DisclosureMode = full | subset | actor-only
~~~

This factoring is editorial. It does not make token shape a substitute for the
explicit `actp` value. Validators, Authorization Servers, current actors, and
recipients MUST apply the rules for the selected `actp` and MUST NOT infer a
different profile from the apparent shape of `act`.

For example, a subset-disclosure token that happens to disclose the full
disclosed actor chain is still a subset-disclosure token, not a full-disclosure token.
Likewise, a subset-disclosure token that happens to disclose only the current
actor is still a subset-disclosure token, not an actor-only token. Full
Disclosure and Actor-Only Disclosure are profile-level commitments expressed
by `actp`, not properties inferred from a single token instance.

## Profile Identifiers and Parameters {#profile-identifiers}

Each value in the following table is used both as the
`actor_chain_profile` token request parameter value and as the `actp` token
claim value.

| `actp` value | Evidence model | Disclosure mode |
| --- | --- | --- |
| `declared-full` | Declared | Full Disclosure |
| `declared-subset` | Declared | Subset Disclosure |
| `declared-actor-only` | Declared | Actor-Only Disclosure |
| `verified-full` | Verified | Full Disclosure |
| `verified-subset` | Verified | Subset Disclosure |
| `verified-actor-only` | Verified | Actor-Only Disclosure |

The evidence model determines how chain continuity is established:

* **Declared** profiles rely on Authorization-Server-asserted chain continuity
  and profiled access token signature validation.
* **Verified** profiles add actor-signed step proofs and cumulative commitment
  state in `actc`.

The disclosure mode determines how much actor-chain information is visible in
profiled access tokens.

## Disclosure Modes {#disclosure-modes}

Disclosure mode is applied to a profile-defined chain for the hop. For declared
profiles, that chain is the Authorization Server's accepted actor-chain state
after appending the authenticated current actor. For verified profiles, that
chain is the actor-visible chain for the hop that is bound into the submitted
step proof.

The following abstract disclosure function describes the output shape:

~~~ text
Disclose(chain, mode, current_actor, policy):

  if mode == full:
      return EncodeVisibleChain(chain)
      act is mandatory

  if mode == subset:
      return EncodeVisibleChain(S), where S is an ordered subsequence of chain
      or omit act entirely when policy permits

  if mode == actor-only:
      return EncodeVisibleChain([current_actor])
      act is mandatory
~~~

This function is explanatory. The normative rules for each mode are below.

### Full Disclosure

Under Full Disclosure, `act` is mandatory in every profiled access token issued under
the profile. The disclosed actor chain, obtained from `VisibleChain(act)`,
MUST equal the complete profile-defined chain for the hop. The Authorization
Server MUST NOT omit `act`, disclose only a subset, or disclose only the
current actor under a Full Disclosure profile.

Recipients and current actors MAY use the complete disclosed actor chain for
profile-specific authorization and continuity decisions. A token issued under a
subset profile that happens to disclose the complete chain MUST NOT be
processed as a Full Disclosure profile token unless its `actp` selects a Full
Disclosure profile.

### Subset Disclosure

Under Subset Disclosure, the Authorization Server MAY disclose a
recipient-specific `act` chain or MAY omit `act` entirely according to local
policy and the selected profile. When `act` is present, the disclosed actor
chain, obtained from `VisibleChain(act)`, MUST be an ordered
subsequence of the profile-defined chain for the hop.

A recipient or current actor MUST use only the actor-chain information actually
disclosed in the artifact. It MUST treat undisclosed prior actors, an
undisclosed current actor, hidden prefixes, adjacency, absence, and exact chain
length as unavailable from that artifact. It MUST NOT infer hidden actors or
chain structure from omitted entries, identifier structure, `actc`, or other
claims.

If an inbound token under a subset profile omits `act`, or discloses `act`
without the current actor, this specification provides no inline current-actor
disclosure for that hop. Any additional authorization inputs are determined by
local policy and are outside the scope of this specification.

A singleton current-actor-only disclosure is syntactically possible under
Subset Disclosure, but it is not an Actor-Only Disclosure profile commitment.
Deployments that require actor-only behavior to be explicit and machine-
readable SHOULD use an Actor-Only Disclosure profile.

### Actor-Only Disclosure

Under Actor-Only Disclosure, `act` is mandatory in every profiled access token issued
under the profile. The disclosed actor chain, obtained from
`VisibleChain(act)`, MUST contain exactly one ActorID identifying the current
actor represented by that token. Prior actors MUST NOT be disclosed inline in
profiled access tokens under an Actor-Only Disclosure profile.

For actor-chain authorization, recipients MUST use only the disclosed current
actor and local policy.
They MUST NOT infer prior actors, chain length, or hidden chain membership from
omission, identifier structure, `actc`, or other claims. A token issued under a
subset profile that happens to disclose only the current actor MUST NOT be
processed as an Actor-Only Disclosure profile token unless its `actp` selects
an Actor-Only Disclosure profile.

## Authorization Rules by Disclosure Mode

The following table summarizes the actor-chain information available for
next-hop authorization under the selected profile.

| Disclosure mode | Profiled access token authorization input |
| --- | --- |
| Full Disclosure | The complete disclosed actor chain for the hop. |
| Subset Disclosure | The disclosed ordered subset only, if any. Undisclosed actors are unavailable from the artifact. |
| Actor-Only Disclosure | The disclosed current actor only. Prior actors are unavailable from the artifact. |

Deployments in which recipient authorization depends on prior-path membership
or order MUST select a profile and disclosure policy that disclose the required
prior-path evidence at that hop. Actor-only outcomes and omitted-`act` outcomes
are not sufficient inputs for path-sensitive authorization decisions.

## Security Properties by Evidence Model and Disclosure Mode

The following list summarizes the security result of the factored profile
model. The detailed normative processing rules remain in the evidence-model and
profile-delta sections below.

* Declared Full Disclosure provides Authorization-Server-asserted continuity
  over the complete disclosed actor chain under the non-collusion assumption.
* Declared Subset Disclosure provides Authorization-Server-asserted continuity
  for the accepted chain state, with profiled access token authorization limited
  to the disclosed subset, if any.
* Declared Actor-Only Disclosure provides Authorization-Server-asserted
  current-actor continuity. Prior actors are available only through retained
  Authorization Server records or other out-of-band evidence.
* Verified Full Disclosure uses actor-signed step proofs and cumulative `actc`
  to bind the complete disclosed actor chain for each hop.
* Verified Subset Disclosure uses actor-signed step proofs and cumulative
  `actc` to bind the actor-visible chain for each hop, while profiled access
  tokens disclose only an ordered subset or omit `act`.
* Verified Actor-Only Disclosure keeps actor-signed step proofs and cumulative
  `actc` available for later review, while profiled access tokens disclose
  exactly the current actor.

# Declared Profiles {#declared-profiles}

The declared profiles use the declared evidence model with one of the three
disclosure modes. They rely on Authorization-Server-asserted chain continuity,
profile-specific disclosure policy, profiled access token signature validation,
and the common validation procedures in this document. They do not use actor-signed
step proofs or `actc`.

Declared profiles assume that an actor does not collude with its home
Authorization Server. Under that non-collusion assumption, prior actors MUST
NOT be silently inserted, removed, reordered, or altered during token exchange
for the disclosed chain state governed by the selected profile.

## Declared Common Processing {#declared-common-processing}

### Declared Bootstrap

At workflow start, the initial actor `A` MUST request a token from the
Authorization Server with at least:

* `grant_type=client_credentials`;
* `actor_chain_profile` set to one of the declared profile identifiers; and
* the requested OAuth targeting parameters (`audience`, `resource`, or both)
  sufficient to identify the initial target context.

If the Authorization Server accepts the request, it MUST authenticate the
initial actor, bind that actor to its ActorID representation, establish the
workflow subject according to local policy, mint a fresh `acti`, and create the
initial accepted actor-chain state `[A]`. The Authorization Server MUST then
issue a profiled access token containing at least `iss`, `actp`, `acti`, `sub`,
`jti`, `aud`, and `exp`, plus `act` as required by the selected disclosure
mode.

At bootstrap and at each later exchange, the chosen `sub` representation MUST
remain consistent with the selected `actp` disclosure constraints. In
particular, `sub` MUST NOT disclose an actor identity or other actor-chain
information that the selected profile is intended to withhold from the relevant
recipient class.

### Declared Chain Extension

For a declared chain-extending token exchange, the current actor MUST submit at
least:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
* `actor_chain_profile` set to the active declared profile identifier;
* the inbound token as the RFC 8693 `subject_token`;
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`; and
* the requested OAuth targeting parameters (`audience`, `resource`, or both as
  needed by local policy) sufficient to identify the next target context.

The current actor MAY additionally submit RFC 8693 `actor_token` and
`actor_token_type` parameters subject to the common validation rules in
{{as-token-exchange-validation}}.

The Authorization Server MUST perform token-exchange validation as described in
{{as-token-exchange-validation}}. It MUST verify that the
requested profile equals the inbound token's `actp`, authenticate the current
actor, verify intended-recipient semantics for the inbound token, preserve
`acti` and `sub` continuity, and enforce profile-specific disclosure rules.

The Authorization Server MUST derive the next-hop accepted chain state from the
accepted workflow state for the inbound hop, append the authenticated current
actor, and issue a returned profiled access token whose `act` is determined by the
selected disclosure mode. It MUST NOT insert, reorder, delete, or alter prior
actors in any disclosed `act`.

Because the returned profiled access token is visible to the current actor in this
base JWT/JWS binding, the Authorization Server MUST NOT disclose in that
returned token any actor identity that the current actor is not permitted to
learn.

### Declared Validation and Authorization

A recipient of a declared-profile token MUST perform recipient validation as
described in {{recipient-validation}} and MUST apply the
disclosure-mode rules for the selected `actp`.

A current actor validating a returned declared-profile token MUST perform
current-actor returned-token validation as described in
{{returned-token-validation}} and MUST apply the disclosure-mode rules for the
selected `actp`.

For declared subset and declared actor-only profiles, the current actor and
downstream recipient validate only the actor-chain information disclosed to
them. They do not independently validate hidden undisclosed portions of the
Authorization Server's retained workflow chain state.

The Authorization Server MAY retain authoritative workflow chain state richer
than the profiled access token `act` disclosure for audit, forensics, legal review,
and branch reconstruction. Such retained state is not available to a recipient
from the profiled access token unless it is disclosed by the selected profile and
policy or made available through another mechanism outside this specification.

## Declared Full Disclosure Profile {#declared-full}

The profile identifier for this profile is `declared-full`.

This profile uses the declared evidence model and Full Disclosure mode.
Accordingly, `act` is mandatory in every profiled access token and
`VisibleChain(act)` MUST equal the complete accepted actor-chain state for the
hop. At bootstrap, the profiled access token MUST contain
`act=EncodeVisibleChain([A])`. At a later hop by current actor `N`, the
returned profiled access token MUST disclose the prior accepted chain state with `N`
appended.

A recipient MUST use the complete disclosed actor chain for actor-chain authorization
where actor-chain authorization is required. A current actor validating a
returned token MUST verify that the returned disclosed actor chain is exactly the
previously verified disclosed actor chain with that current actor appended.

## Declared Subset Disclosure Profile {#declared-subset}

The profile identifier for this profile is `declared-subset`.

This profile uses the declared evidence model and Subset Disclosure mode.
Accordingly, the Authorization Server MAY disclose a recipient-specific ordered
subsequence of the accepted chain state for the hop, or MAY omit `act`
entirely according to local policy. If `act` is present, `VisibleChain(act)`
MUST be an ordered subsequence of the accepted chain state for that hop.

A recipient MUST authorize using only the disclosed actor chain, if any, and
MUST treat undisclosed actors as unavailable. If the token omits `act`, or
discloses `act` without the current actor, this specification provides no
inline current-actor disclosure for that hop.

Cross-domain re-issuance under this profile preserves only the disclosed
asserted chain state carried in the inbound token unless a trusted companion
mechanism
explicitly transfers additional hidden state. This profile does not provide the
step-proof-based accountability or cumulative commitment state of the verified
profiles.

## Declared Actor-Only Disclosure Profile {#declared-actor-only}

The profile identifier for this profile is `declared-actor-only`.

This profile uses the declared evidence model and Actor-Only Disclosure mode.
Accordingly, `act` is mandatory in every profiled access token and
`VisibleChain(act)` MUST equal `[current_actor]`. The Authorization Server MUST
NOT disclose prior actors inline in profiled access tokens under this profile.

A recipient MUST authorize only on the disclosed current actor and local policy.
Prior actors remain available only through Authorization Server records or
other out-of-band evidence.

# Verified Profile Proof Input Model {#verified-proof-input}

## Proof Input Template

The verified profiles use a limited number of proof-input templates. This
section defines them once so that the verified profile sections can state only
their profile-specific substitutions. Canonicalization, hashing, and commitment
construction are defined in {{canonicalization-commitment}}.

Let:

* `profile` be the active `actp` value;
* `acti` be the stable actor-chain identifier;
* `prev_state` be either the returned base64url `initial_chain_seed` from
  bootstrap or the verified prior commitment digest string from `actc.curr`, as
  required by the profile;
* `visible_actor_chain_for_hop` be the exact ordered actor-visible chain for
  the hop after appending the authenticated current actor;
* `workflow_sub` be the exact preserved workflow `sub` string for the hop being
  extended within the current issuer domain;
* `TC_next` be the canonical `target_context` for the next hop, often the
  object `{ "aud": aud }` but extended when local policy needs finer-grained
  target binding;
* `iat_N` be the JWT NumericDate at which actor `N` signs the step proof; and
* `[N]` denote the canonical ActorID JSON object representation of the
  authenticated current actor.

Symbols such as `TC_B`, `TC_C`, and `TC_next` denote the canonical
`target_context` for the corresponding next hop.

Proof-bound profiles instantiate the following generic step-proof payload
template:

~~~ json
Sign_N({
  "ctx": ds(profile),
  "acti": acti,
  "prev": prev_state,
  "sub": workflow_sub,
  "act": EncodeVisibleChain(visible_actor_chain_for_hop),
  "target_context": TC_next,
  "iat": iat_N
})
~~~

The domain-separation string `ds(profile)` is profile-specific:

* `actor-chain-verified-full-step-sig-v1` for `verified-full`;
* `actor-chain-verified-subset-step-sig-v1` for `verified-subset`; and
* `actor-chain-verified-actor-only-step-sig-v1` for `verified-actor-only`.

These strings remain distinct even though the verified branch step-proof
payload members are structurally aligned. The signed step-proof payload does
not carry `actp` or another explicit profile identifier, and the meaning of the
`act` member remains profile-dependent. Distinct domain-separation strings are
therefore REQUIRED to bind the proof to the intended verified profile semantics
and to prevent cross-profile proof confusion or accidental proof reuse.

The trailing `-v1` suffix in each domain-separation string identifies the
step-proof payload version defined by the initial standardized version of this
specification. During Internet-Draft development before that version is
standardized, changes to the step-proof payload can still be incorporated into
`-v1`. After the initial standardized version is published, any revision that
changes the membership, semantics, or canonicalization of the step-proof payload
in a non-compatible way MUST allocate a new suffix, such as `-v2`. Verifiers
MUST reject a step proof whose `ctx` value does not exactly match an expected,
implemented domain-separation string for the active `actp`. Verifiers MUST NOT
accept a step proof signed under a different version suffix as equivalent.

In same-domain verified chain-extension hops, the step proof also binds the
exact preserved workflow `sub` string for that hop. This protects against
same-domain silent subject substitution without requiring this base
specification to cryptographically bind later cross-domain `sub` aliasing.

For verified profiles, `visible_actor_chain_for_hop` is the actor-visible chain
that the current actor is permitted to know and extend for that hop. It is not
necessarily the same as the disclosed `act` in the returned profiled access
token.

The profile-specific meaning of `visible_actor_chain_for_hop` is:

* for `verified-full`, the complete disclosed actor chain for the hop after appending the
  authenticated current actor;
* for `verified-subset`, the exact inbound disclosed actor chain verified by the
  current actor, or the empty chain if no `act` was disclosed, with the current
  actor appended; and
* for `verified-actor-only`, the exact inbound disclosed actor chain verified
  by the current actor, with the current actor appended, even though the
  returned profiled access token later discloses only `[N]`.

For verified subset and verified actor-only profiles, the actor-visible chain
signed by the current actor can be broader than the disclosed `act` in the
returned profiled access token. The returned profiled access token's `act` is therefore
not necessarily the complete signed proof input.

# Verified Profiles {#verified-profiles}

The verified profiles use the verified evidence model with one of the three
disclosure modes. They add actor-signed step proofs and cumulative commitment
state in `actc` to the common actor-chain model. Each verified profile inherits
the common model, token requirements, proof input model, validation procedures,
and common verified processing below except as modified by its disclosure mode
or profile-specific delta.

## Common Processing for the Verified Branch {#verified-common-processing}

This section defines the bootstrap, proof, commitment, token-exchange, and
returned-token rules shared by the three verified profiles. In this branch,
profiled access tokens still carry the hop-to-hop token state, but each chain-
extending hop is also backed by an actor-signed step proof and cumulative
commitment state.

### Common Parameters

Each verified profile supplies the following profile-specific parameters to the
common processing below.

| Profile | `actp` value | Step-proof domain-separation string | Returned `act` |
| --- | --- | --- | --- |
| Verified Full Disclosure | `verified-full` | `actor-chain-verified-full-step-sig-v1` | Complete verified disclosed actor chain |
| Verified Subset Disclosure | `verified-subset` | `actor-chain-verified-subset-step-sig-v1` | Ordered subsequence, or omitted `act` |
| Verified Actor-Only Disclosure | `verified-actor-only` | `actor-chain-verified-actor-only-step-sig-v1` | Singleton current actor |

For Verified Full Disclosure, the proof-bound actor-visible chain is the
complete actor-visible chain for the hop after appending the current actor. For
Verified Subset Disclosure and Verified Actor-Only Disclosure, the proof-bound
actor-visible chain is the exact inbound disclosed actor chain verified by the
current actor, with that actor appended.

The profile identifier, step-proof domain-separation string, and the
profile-specific interpretation of `act` remain aligned across the verified
branch.

### Common Bootstrap Context Request {#verified-bootstrap-context}

At workflow start, the initial actor MUST request a bootstrap context from the
Authorization Server's `actor_chain_bootstrap_endpoint` using at least:

* `grant_type=urn:ietf:params:oauth:grant-type:actor-chain-bootstrap`;
* the selected verified profile `actor_chain_profile`; and
* the requested OAuth targeting parameters (`audience`, `resource`, or both)
  sufficient to identify the initial target context.

The Authorization Server MUST authenticate the initial actor, bind that actor
to its ActorID representation, select a commitment hash algorithm, mint a fresh
`acti`, choose a stable workflow-subject representation for `sub`, derive the
bootstrap target context from the requested targeting parameters, and return a
bootstrap response containing at least:

* `actor_chain_bootstrap_context`, an opaque bootstrap handle;
* `acti`;
* `sub`;
* `halg`;
* `target_context`, the exact canonical bootstrap-bound target context against
  which the initial step proof will be validated; and
* `initial_chain_seed`, a base64url value to be used as `prev_state` for the
  initial verified step proof.

The `initial_chain_seed` MUST be generated using a CSPRNG with at least 128
bits of entropy, MUST be unique per workflow instance, and MUST NOT be derived
solely from `acti` or other predictable inputs.

The bootstrap context MUST be integrity-protected by the Authorization Server,
bound to the authenticated initial actor, the selected verified profile, the
chosen `acti`, `sub`, `halg`, and the bootstrap target context, and be
short-lived. It authorizes issuance of initial verified profiled access tokens for
that workflow instance while it remains valid.

For a given canonical chosen initial `target_context`, the Authorization Server
MUST treat repeated redemption of the same bootstrap handle as an idempotent
retry and MUST return the previously accepted initial state, or an equivalent
token representing that same accepted initial state. It MUST NOT issue a second
distinct accepted initial state for that same canonical chosen initial
`target_context`.

The Authorization Server MAY accept additional redemptions of the same
bootstrap handle for distinct canonical chosen initial `target_context` values,
thereby minting multiple accepted initial successors that share the same `acti`
and `initial_chain_seed`. If a deployment expects multiple distinct initial
successors under the same nominal target, the chosen initial `target_context`
MUST include a unique `request_id`.

### Common Initial Actor Step Proof and Bootstrap Issuance {#verified-initial-step}

After receiving the bootstrap response, the initial actor `A` MUST choose the
initial target context to be used for the first issued token. That chosen
initial target context MUST be identical to, or a locally authorized narrowing
of, the canonical bootstrap-bound `target_context` returned in the bootstrap
response. Because there are no prior actors at workflow start, the
profile-defined actor-visible chain for that initial hop is `[A]` for all
verified profiles. `A` MUST then sign an `actor_chain_step_proof` over that
initial actor-visible chain, the exact preserved workflow `sub` string returned
in the bootstrap response, the chosen initial target context, and a signing
`iat`, and redeem the bootstrap context at the token endpoint using at least:

* `grant_type=client_credentials`;
* the selected verified profile `actor_chain_profile`;
* `actor_chain_bootstrap_context`;
* `actor_chain_step_proof`; and
* the requested OAuth targeting parameters (`audience`, `resource`, or both)
  sufficient to identify that chosen initial target context.

The Authorization Server MUST verify the bootstrap context and verify that the
authenticated actor redeeming it is the same actor to which the bootstrap
context was issued. It MUST also verify that the requested profile matches the
bound bootstrap profile, that the chosen target context is identical to or
narrower than the bootstrap-bound target context according to local policy,
that the submitted step proof `ctx` equals the active profile's domain-
separation string, that the submitted step proof `sub` equals the bound
workflow `sub` string, that the submitted step proof `target_context` equals
the chosen target context, that the submitted step proof `iat` is acceptable
under {{jwt-step-proof}}, and that the submitted step proof is otherwise valid.
It then creates the initial `actc` and issues a profiled access token containing
at least `iss`, `actp`, `acti`, `sub`, `jti`, `aud`, `exp`, and `actc`, plus
`act` as required by the selected disclosure mode. The issued token target
claims MUST be identical to or narrower than the chosen target context.

Because the initial verified hop has no prior actors, the exact verified
actor-visible chain for that hop is `[A]`. The returned profiled access token
MUST disclose that chain as `act=EncodeVisibleChain([A])` for `verified-full`
and `verified-actor-only`. For `verified-subset`, the Authorization Server MAY
either disclose `act=EncodeVisibleChain([A])` or omit `act` entirely according
to local policy. When `verified-subset` omits bootstrap `act`, subsequent
disclosed visible-predecessor continuity begins from the empty disclosed chain,
while commitment continuity remains anchored by the initial verified step proof
and `actc`.

### Common Hop Processing

When a current actor `N` receives an inbound verified-profile token, it MUST:

* validate the inbound token and any required `actc`;
* determine, under local policy, any presenting-actor identity for the inbound
  hop needed by the selected profile;
* derive the profile-defined actor-visible chain for the new hop;
* sign `actor_chain_step_proof` over that actor-visible chain, the preserved
  workflow `sub` string for the hop, the next target context, and a signing
  `iat`; and
* submit the inbound token plus the step proof in a token exchange request to
  its home Authorization Server.

### Common Token Exchange

For a chain-extending verified-profile token exchange, the current actor MUST
submit at least:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
* the selected verified profile `actor_chain_profile`;
* the inbound token as the RFC 8693 `subject_token`;
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`;
* `actor_chain_step_proof`; and
* the requested OAuth targeting parameters sufficient to identify the next
  target context.

The current actor MAY additionally submit RFC 8693 `actor_token` and
`actor_token_type` parameters subject to the common validation rules in
{{as-token-exchange-validation}}.

The Authorization Server MUST validate the inbound token and the submitted step
proof for the active profile. It MUST derive the accepted target context from
the token-exchange request and verify that the step proof `target_context`
equals that accepted target context, unless the Authorization Server explicitly
narrows the requested authority. If the Authorization Server narrows the
authority, the narrowed accepted target context MUST be identical to or narrower
than the proof-bound `target_context`.

The Authorization Server MUST verify that the step proof `ctx` equals the
active profile's domain-separation string, that the step proof `sub` equals the
preserved workflow `sub` string for the hop being extended, that the step proof
`iat` is acceptable under {{jwt-step-proof}}, and that the step proof's `act`
equals the profile-defined actor-visible chain for the hop. It MUST verify
append-only processing of that actor-visible chain, update `actc`, and return a
profiled access token whose disclosed `act` representation matches the selected
disclosure mode and whose target claims, including `aud` and any `resource` or
target-context representation used by the deployment, are identical to or
narrower than the accepted target context. The Authorization Server MUST NOT
issue a profiled access token whose target authority is broader than, or
semantically unrelated to, the proof-bound `target_context`. Replay,
idempotency, and multiple-successor handling for submitted step proofs are
defined in {{replay-freshness}}.

For `verified-subset` and `verified-actor-only`, step proofs and `actc` values
MUST be computed over the exact actor-visible chain for the hop, not over a
hidden canonical full chain that the current actor was not permitted to see.

### Common Returned-Token Validation

When validating a returned verified-profile token, the current actor MUST
perform the common returned-token validation in {{returned-token-validation}}
and MUST also verify:

* that `actc` is present and valid;
* that the returned token preserves `acti`, `actp`, and `sub` as required;
* that the embedded `actc` payload preserves the expected `acti`, `actp`, and
  `halg` values for the active workflow state;
* that `actc.prev` equals the previously verified prior commitment digest, or
  the `initial_chain_seed` for the initial verified hop;
* that `actc.step_hash` equals `b64url(Hash_halg(step_proof_bytes))` computed
  over the exact compact JWS string submitted as `actor_chain_step_proof` for
  that hop;
* that the returned token target claims are identical to or narrower than the
  proof-bound target context for that hop; and
* any profile-specific disclosed-chain checks for the active disclosure mode.

If the returned artifact or companion validation interface does not expose
enough target information to perform the target check above, the current actor
MUST treat that condition as a profile-validation failure.

Because `actc` is cumulative commitment state carried inline in profiled
access tokens issued under verified profiles, every later actor and every
Authorization Server that
extends the verified workflow relies on that inline `actc` value. Online
validation of an inbound or returned `actc` proves issuer-signed commitment
continuity and internal commitment consistency. It does not by itself prove the
semantic meaning of `step_hash` against the underlying step proof unless the
exact step proof bytes and related verification material are also retained or
discoverable for later audit. Deployments MAY vary on whether every terminal
recipient performs synchronous `actc` validation at admission time, but chain
extension MUST NOT proceed without successful validation of the inbound `actc`.

For non-repudiation, participation, or later semantic interpretation,
deployments SHOULD retain the exact step-proof artifact and associated
verification context used when validating commitment linkage.

For `verified-subset` and `verified-actor-only`, the current actor's signature
provides non-repudiation only over the exact actor-visible chain for that hop
and the linked prior commitment digest, not over hidden prefix semantics that
the actor was not permitted to verify.

## Verified Full Disclosure Profile {#verified-full}

The profile identifier for this profile is `verified-full`.

This profile uses the verified evidence model and Full Disclosure mode.
Accordingly, `act` is mandatory in every profiled access token and
`VisibleChain(act)` MUST equal the complete verified actor-visible chain for
the hop.

For a current actor `N`, let `chain_in` be the complete disclosed actor chain verified from
the inbound token. If `N` establishes a presenting actor for the inbound hop
under local policy, `N` MUST verify that the last actor in `chain_in` is that
same presenting actor. The exact actor-visible chain for the hop is:

~~~ text
visible_hop_N = chain_in + [N]
~~~

The Authorization Server MUST issue `EncodeVisibleChain(visible_hop_N)` as
the disclosed `act` in the returned token. A recipient MUST use the complete
disclosed actor chain for actor-chain authorization where actor-chain
authorization is required.

A claim that actor `V` participated in the chain MUST fail unless a valid step
proof for `V` can be produced and verified against the corresponding prior
commitment state and `acti`. If an actor is omitted from a later disclosed actor chain,
that omitted actor MAY prove prior participation by presenting an earlier token
showing the prior chain state and the corresponding commitment state and
verifiable step proof, or an immutable Authorization Server exchange record. A
denial of participation by actor `X` MUST fail if a valid step proof for `X` is
available and verifies.

## Verified Subset Disclosure Profile {#verified-subset}

The profile identifier for this profile is `verified-subset`.

This profile uses the verified evidence model and Subset Disclosure mode.
Accordingly, the Authorization Server MAY disclose a recipient-specific ordered
subsequence of the verified actor-visible chain for the hop, or MAY omit `act`
entirely according to local policy. If `act` is present, `VisibleChain(act)`
MUST be an ordered subsequence of the verified actor-visible chain for that
hop.

For a current actor `N`, let `chain_in` be the exact disclosed inbound visible
chain that `N` verified from the inbound token, or the empty chain if the
inbound token disclosed no `act`. If `chain_in` is non-empty and `N`
establishes a presenting actor for the inbound hop under local policy, `N` MUST
verify that its last actor is that same presenting actor. The exact verified
actor-visible chain for the hop is:

~~~ text
visible_hop_N = chain_in + [N]
~~~

The current actor `N` MUST append only itself and MUST NOT insert, delete, or
reorder prior actors within `chain_in`. The Authorization Server MUST verify
that the submitted actor-visible chain equals the exact inbound disclosed chain
previously verified by `N`, with `N` appended. An omitted inbound `act`
corresponds to the empty `chain_in` value.

When validating a returned token, `N` MUST verify, if the returned token
discloses `act`, that the disclosed actor chain is an ordered subsequence of
the exact verified actor-visible chain that `N` signed for that hop.

A recipient MAY use the verified disclosed actor chain for authorization
decisions, but MUST use only the disclosed subset and MUST treat undisclosed
prior actors as unavailable. If the token omits `act`, or discloses `act`
without the current actor, this specification provides no inline current-actor
disclosure for that hop.

Different recipients MAY receive different valid disclosed subsets derived from
the same verified actor-visible chain according to local disclosure policy.
That alone does not constitute an integrity failure. A malicious or compromised
Authorization Server could still attempt to issue a disclosed subset
inconsistent with the verified actor-visible chain. Such an inconsistency MUST
fail if the retained step proof for that hop or an immutable Authorization
Server exchange record is later checked.

An actor omitted from a disclosed chain MAY still prove prior participation by
presenting the corresponding step proof or immutable Authorization Server
exchange record for the verified actor-visible chain for the relevant hop.
When this profile omits `act`, or discloses only a narrow subset, later
reconstruction of the full accepted chain from step proofs alone is not
guaranteed. Such reconstruction can require retained Authorization Server
records or other authoritative workflow evidence.

## Verified Actor-Only Disclosure Profile {#verified-actor-only}

The profile identifier for this profile is `verified-actor-only`.

This profile uses the verified evidence model and Actor-Only Disclosure mode.
Accordingly, `act` is mandatory in every profiled access token and
`VisibleChain(act)` MUST equal `[current_actor]`. Prior actors MUST NOT be
disclosed inline in profiled access tokens under this profile. The returned profiled access
token MUST still carry the updated cumulative `actc` state.

For each hop under this profile, the current actor MUST construct the verified
actor-visible chain as the exact inbound disclosed actor chain that the actor
verified, with that actor appended. The step proof MUST carry that exact
actor-visible chain in its `act` member, even though the returned profiled access
token later discloses only the current actor.

Upon receipt of the returned token, the current actor MUST verify that the
returned `act` consists only of the current actor and that the returned
`actc` matches the accepted successor state for the verified hop.

Upon receipt of the token, the next recipient MUST perform recipient validation
and, for actor-chain authorization, use only the disclosed current actor and
local policy. If the
recipient establishes a presenting actor for the inbound token under local
policy, it MUST also confirm that the disclosed current actor matches that same
presenting actor.

If a returned profiled access token under this profile discloses any prior actor
inline, the current actor MUST reject it. If a recipient under this profile
attempts to infer hidden prior actors from omission, identifier structure, or
`actc` alone, that behavior is out of profile and MUST NOT be treated as a
conforming authorization decision.

# Same-Domain, Cross-Domain, and Branching Behavior {#domain-branching}

## Same-Domain and Cross-Domain Hops {#same-cross-domain-hops}

Within one trust domain, the current actor exchanges its inbound token at its
home Authorization Server, meaning the Authorization Server that validates the
prior chain state for that actor and issues the next profiled access token.

Across a trust boundary, if the next recipient does not trust the current
Authorization Server directly, the current actor performs a second token
exchange at the next domain's Authorization Server. That second exchange
preserves the already-established chain state and does not append the next
recipient.

The trust/evidence differences among profiles are summarized in
{{profile-summary}} and discussed further in {{trust-audit}}. The special
preserve-state cases for cross-domain re-issuance and Refresh-Exchange are
defined in {{preserve-state-exchanges}}.

## Branching and Non-Goals {#branching-non-goals}

Application logic may branch, fan out, and run in parallel. This document
standardizes one disclosed path per issued token, not a full call-graph language.
An Authorization Server MAY mint multiple accepted successor tokens from one
prior accepted state, each with its own `jti` and canonical `target_context`.
Such successor tokens MAY share the same `acti` and earlier workflow history.
Deployments that require strict linear continuation MAY instead enforce a local
single-successor policy under which the Authorization Server accepts at most one
successor from any accepted prior state. This base specification does not
define an interoperable on-the-wire signal for single-successor mode, sibling
invalidation, or proof that no parallel successor exists. This document does
not define merge semantics, sibling-discovery semantics, or inline
branch-selection semantics.

Accordingly, a valid token under this specification proves only one accepted
disclosed path for that token. It does not by itself prove branch uniqueness for
the workflow instance or prove that no other accepted sibling successor exists.

Post-facto reconstruction of branching is a forensic or legal-audit concern,
not a normal online authorization requirement. Retained Authorization Server
records, timestamps, commitment state, and causal links among presenting
actors, current actors, and subsequent actors can often reveal much of the
effective call graph, but this base specification alone does not guarantee a
complete standardized graph across all branches.

Each chain-extending issued token and each step proof binds exactly one logical
next-hop target context, as defined in {{target-context}}. Additional target
contexts or independently callable recipients require additional successor
tokens.

Repeated ActorID values within one workflow instance are permitted. A sequence
such as `[A,B,C,D,A,E]` denotes that actor `A` acted more than once in the
same workflow instance. Collecting all accepted hop evidence for one `acti`,
such as retained tokens, proofs, commitments, and exchange records, can
therefore reconstruct the accepted hop sequence, including repeated-actor
revisits.

# Special Preserve-State Exchanges {#preserve-state-exchanges}

A preserve-state exchange is a token exchange that preserves previously
accepted actor-chain state without appending a new actor. This document defines
two preserve-state exchanges: cross-domain re-issuance and Refresh-Exchange.
They are easiest to read after the profile flows.

A token-exchange request under this specification MUST NOT set both
`actor_chain_cross_domain=true` and `actor_chain_refresh=true`. These
parameters select different preserve-state processing modes. Setting both would
make subject handling, issuer handling, target-context narrowing, and returned-
token validation ambiguous. The Authorization Server MUST reject any request
that sets both rather than choosing one interpretation.

For preserve-state exchanges (`actor_chain_cross_domain=true` or
`actor_chain_refresh=true`), the Authorization Server MUST apply an explicit
preserve-state authorization policy. Unless deployment policy explicitly
selects transport-only renewal semantics, the Authorization Server MUST
re-evaluate current authorization for the authenticated requester and the
requested target context before issuing the preserved-state token. If current
policy does not permit issuance, the Authorization Server MUST reject the
request.

For any preserve-state exchange, the Authorization Server MUST establish the
ActorID represented by the preserved current-actor state and MUST verify that
the authenticated requester is that ActorID or is explicitly authorized to
preserve state for that ActorID. The represented ActorID MAY be established
from disclosed `act`, a confirmation or token-binding mechanism,
issuer-retained state, introspection, or a standardized presenter proof. If the
represented ActorID cannot be established, or if the requester is neither that
ActorID nor an authorized delegate, the Authorization Server MUST reject the
request with `invalid_grant`.

## Cross-Domain Re-Issuance {#cross-domain-reissuance}

### Request Format

If the next hop does not trust the current Authorization Server directly, the
current actor MUST perform a second token exchange at the next domain's
Authorization Server.

A cross-domain re-issuance request MUST include:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
* `actor_chain_cross_domain=true`;
* `actor_chain_profile` set to the active profile identifier carried by the
  inbound token;
* the current inbound actor-chain token as the RFC 8693 `subject_token`;
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`; and
* any requested OAuth targeting parameters (`audience`, `resource`, or both)
  for the local target context to be minted by the re-issuing Authorization
  Server.

The re-issuing Authorization Server MUST ensure that any locally minted target
context is semantically equivalent to, or narrower than, the target context
authorized by the inbound token according to local trust policy and audience
mapping rules. When the earlier chain-extending hop bound a `target_context`
richer than plain `aud`, the re-issuing Authorization Server MUST evaluate
that equivalence or narrowing against the exact retained or otherwise
recoverable prior `target_context`, not against `aud` alone. It MUST NOT issue
a local token whose target context is broader than, or semantically unrelated
to, the target context authorized by the inbound token. Unknown or unmapped
`target_context` members MUST be handled according to {{target-context}}; they
MUST NOT be ignored during cross-domain equivalence or narrowing.

A cross-domain re-issuance request MUST NOT append the chain and MUST NOT
submit `actor_chain_step_proof`, because this exchange preserves rather than
extends the accepted chain state. The `actor_chain_cross_domain` parameter is
the explicit wire signal that the request is for preservation and local
re-issuance rather than ordinary same-domain chain extension.

### Preservation Rules

The cross-domain Authorization Server MUST:

* validate the inbound token signature and issuer trust according to local
  policy;
* validate the selected actor-chain profile;
* validate the preserved disclosed-chain structure;
* preserve `actp`;
* preserve `acti`;
* preserve `actc`, if present, exactly as verified;
* enforce preserve-state authorization policy for this re-issuance request as
  required above;
* continue to represent the same established current ActorID; and
* not append the next recipient.

Disclosed `act` handling during cross-domain re-issuance is profile-specific:

* for the Full Disclosure profiles and the Actor-Only profiles, the re-issuing
  Authorization Server MUST preserve the disclosed `act` exactly, except that if
  an inbound disclosed node omitted `iss`, the re-issuing Authorization Server
  MAY materialize that `iss` explicitly only to preserve the same ActorID
  semantics;
* for the Subset Disclosure profiles, if the inbound token discloses `act`, the
  re-issuing Authorization Server MAY preserve that disclosed `act` exactly,
  disclose any ordered subsequence of that inbound disclosed actor chain, or omit `act`
  entirely according to local policy; it MUST NOT introduce any actor not
  present in the inbound disclosed actor chain, reorder actors, or use hidden retained
  state to broaden disclosure; when a returned disclosed node would otherwise
  rely on inherited issuer context, the re-issuing Authorization Server MAY
  materialize the corresponding `iss` explicitly only to preserve the same
  ActorID semantics; and
* if the inbound token omits `act`, the re-issuing Authorization Server MUST
  NOT synthesize a disclosed `act` from hidden retained state.

### Subject Handling {#cross-domain-subject}

For top-level `sub`, the re-issuing Authorization Server SHOULD preserve the
exact inbound value when doing so preserves the same underlying subject
semantics and does not broaden disclosure. If exact preservation would change
subject semantics under the new issuer namespace or would disclose more than the
inbound token disclosed, the re-issuing Authorization Server MAY translate
`sub` into a local alias that denotes the same underlying subject and MUST
retain an audit binding between the old and new subject representations. If the
re-issuing Authorization Server cannot establish same-subject semantic
continuity without broader disclosure, it MUST reject the request. Once such a
local alias is accepted in cross-domain re-issuance, that returned `sub` value
becomes the preserved workflow-subject representation for later same-domain
validation within the new issuer domain.

This specification cryptographically binds same-domain workflow-subject
continuity through verified step proofs. It does not cryptographically bind
cross-domain `sub` alias continuity in preserved `actc`. Accordingly,
preserved `actc` continuity across cross-domain re-issuance MUST NOT be
interpreted as cryptographic proof that the pre-translation and post-
translation `sub` values are bound by this specification to the same subject
representation. In this version, cross-domain subject-alias continuity remains
a matter of Authorization-Server policy and retained audit evidence.

Future companion specifications MAY define privacy-preserving Authorization
Server-to-Authorization Server transfer of additional hidden workflow state.
Such mechanisms are outside this base specification. This document's cross-
domain rules preserve only the disclosed state allowed by policy together with
any preserved `actc` state defined here.

### ActorID Namespace Handling

Each disclosed `act` entry uses ActorID semantics over (`iss`, `sub`). If an
inbound `act` node omitted `iss`, the re-issuing Authorization Server MUST
preserve the same ActorID semantics by emitting an explicit `iss` equal to the
inbound token's issuer together with the same actor `sub`, rather than relying
on the new local token issuer as an implicit namespace. Internal canonicalization
for proof, comparison, and ordered-subsequence evaluation in this document
therefore always uses fully materialized ActorID pairs.

The cross-domain Authorization Server MAY mint a new local `jti`, apply a new
local expiry, change token format or envelope, and add local trust or policy
claims. If cross-domain re-issuance narrows or locally rewrites the target
context, retained step proofs and preserved `actc` continue to reflect the
target context that was bound during the original chain-extending hop, not the
narrower or rewritten token audience issued by the re-issuing Authorization Server.

Accordingly, when such narrowing or rewriting occurs, the current re-issued
token's audience or other local target representation MUST NOT be interpreted
as if it were itself the target context cryptographically bound by the earlier
step proof or by preserved `actc`. In this case, the re-issued token carries a
current presentation context for local use, while the preserved proof-bound
context remains that of the original chain-extending hop.

A recipient or current actor in the new domain that trusts the re-issuing
Authorization Server MAY rely on that enclosing token signature as attestation
that any preserved foreign `actc` was validated and carried forward unchanged.
Such a recipient need not independently validate a foreign Authorization
Server's JWS signature on the preserved `actc` unless local policy or audit
requires it.

The base specification does not define a portable cryptographic lineage field
that identifies the exact inbound token instance from which a returned cross-
domain re-issued token was derived. Accordingly, exact input-token provenance
for a re-issued token remains a matter of Authorization-Server records or of a
future companion specification that defines such a lineage field.

### Returned-Token Validation

When validating a token returned by cross-domain re-issuance, the current actor
does not recompute a new commitment object from a new step proof. Instead, it
MUST verify the token signature and MUST verify that preserved chain-state
fields, including `actp`, `acti`, and `actc`, preserve the same accepted chain
state as the inbound token except where this specification explicitly permits
cross-domain re-issuance changes such as local `sub` aliasing under the
semantic-equivalence rule, local `jti`, local `exp`, token format or envelope,
approved local trust and policy claims, or explicit `iss` materialization in
`act` solely to preserve the same ActorID semantics when an inbound node had
omitted `iss`. For Full Disclosure and Actor-Only profiles, any returned
disclosed `act` MUST preserve the inbound disclosed `act` exactly except for
such permitted `iss` materialization. For Subset Disclosure profiles, any
returned disclosed `act`, if present, MUST be an ordered subsequence of the
inbound disclosed actor chain and MUST NOT introduce any actor not disclosed in
the inbound token. The returned token target authority MUST be identical to or
narrower than the prior accepted target context, subject to the cross-domain
mapping rules in {{target-context}} and {{cross-domain-reissuance}}.

## Refresh-Exchange {#refresh-exchange}

A current actor MAY use token exchange to refresh a short-lived transport token
without appending the actor chain or regenerating a step proof.

### Request Format

A Refresh-Exchange request MUST include:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
* `actor_chain_refresh=true`;
* `actor_chain_profile` set to the active profile identifier carried by the
  inbound token;
* the current inbound actor-chain token as the RFC 8693 `subject_token`;
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`;
* the authenticated requester that is continuing that accepted chain state as
  the represented current ActorID or as an authorized delegate; and
* any requested OAuth targeting parameters (`audience`, `resource`, or both).
  If omitted, the requested target context is the same as the inbound token's
  target context as represented by `aud` and any locally retained
  target-selection context associated with that accepted token state.

A Refresh-Exchange request MUST NOT include `actor_chain_step_proof`, because
Refresh-Exchange preserves rather than extends the accepted chain state.

A Refresh-Exchange request MUST NOT broaden the active profile, represented
current ActorID, disclosed actor chain state visible to the current actor,
commitment state, or target context. The requested target context MUST be
identical to, or a locally authorized narrowing of, the target context already
represented by the inbound token and any associated retained target-selection
state according to local policy. Such narrowing MUST preserve the same
recipient identity; it MUST NOT retarget the token to an audience or resource server not
already present in the inbound token's canonical `target_context`.

### Processing Rules

When processing Refresh-Exchange, the Authorization Server MUST:

* validate the inbound token and establish the represented current ActorID as
  required for preserve-state exchanges;
* verify that the requested profile identifier exactly matches the inbound
  token's `actp`;
* verify intended-recipient semantics as applicable;
* enforce preserve-state authorization policy for this refresh request as
  required above;
* verify that the request does not append the chain, alter preserved chain
  state, broaden target context, or change recipient identity; and
* issue a replacement token with a new `jti` and refreshed `exp`.

For Refresh-Exchange, the Authorization Server MUST preserve `acti`,
`actp`, `sub`, `act`, if present, and `actc`, if present,
exactly as verified for the current actor. A new step proof MUST NOT be
required, and a new commitment object MUST NOT be created. If Refresh-Exchange
narrows the target context, retained step proofs and preserved `actc` continue
to reflect the target context that was bound during the original
chain-extending hop, not the narrower refreshed target context.

This specification does not define or require any particular token-binding,
presenter-binding, or key-transition mechanism for Refresh-Exchange. If a
deployment changes such transport or authentication properties during refresh,
that handling is governed by local policy and any companion specifications
rather than by this document. Historical step proofs remain bound to the keys
used when those proofs were created and MUST be verified against those
historical bindings, not against later local authentication material.

A recipient or coordinating component MUST treat a token obtained by
Refresh-Exchange as representing the same accepted chain state as the inbound
token from which it was refreshed. If local policy records a presenter-binding
or key-transition event, later verifiers rely on those local records or other
retained evidence for that event itself.

### Returned-Token Validation

When validating a token returned by Refresh-Exchange, the current actor does
not recompute a new commitment object from a new step proof. Instead, it MUST
verify the token signature and MUST verify that preserved chain-state fields,
including `actp`, `acti`, `sub`, `act`, and `actc`, are unchanged from the
inbound token except where this specification explicitly permits refresh-
specific changes such as `jti`, `exp`, or locally managed transport metadata.

# Optional Receiver Acknowledgment Extension {#hop-ack}

A recipient MAY produce a receiver acknowledgment artifact, called `hop_ack`,
for an inbound actor-chain token. This OPTIONAL extension does not alter chain
progression semantics.

A valid `hop_ack` provides signed evidence that the recipient accepted
responsibility for the identified hop, bound to the actor-chain identifier, the identified inbound hop
state, recipient, target context, and the acknowledged inbound token instance
via `inbound_jti`. For verified profiles, the stronger workflow-level
correlation anchors are `acti` together with the inbound commitment digest for
that hop; `inbound_jti` remains the token-instance trace field. If the
deployment establishes a presenter ActorID for the acknowledged hop under local
policy, `hop_ack` MAY additionally bind that presenter. For declared profiles,
the inbound hop state is the validated disclosed `act` from the inbound token
when that profile disclosed `act` on the acknowledged hop. For verified profiles,
that inbound hop state is the verified inbound commitment digest extracted from
the inbound token's `actc.curr`.

A recipient can issue a valid `hop_ack` only if it can either deterministically
derive or receive the exact canonical `target_context` value for the
acknowledged hop. When `target_context` extends beyond plain `aud`, the caller
or a coordinating component MUST communicate that exact canonical JSON value to
the recipient by an integrity-protected application mechanism before expecting
a matching `hop_ack`.

A `hop_ack` is ordinarily returned to the presenting actor or to a coordinating
component acting for that hop. It MAY later be archived, forwarded, or made
available to an audit service or other authorized dispute-resolution component
under local policy.

`hop_ack` MUST NOT by itself append the recipient to the actor chain.

A recipient MUST NOT emit `hop_ack` with status `accepted` until it has either:

* completed the requested operation; or
* durably recorded sufficient state to recover, retry, or otherwise honor the
  accepted request according to local reliability policy.

A deployment MAY require `hop_ack` for selected hops, including terminal hops.
Deployments that require evidence of terminal acceptance SHOULD require a valid
`hop_ack` for those terminal hops.
When `hop_ack` is required by policy, the calling actor and any coordinating
component MUST treat that hop as not accepted unless a valid `hop_ack` is
received and verified.

Deployments that rely on `hop_ack` for later audit or dispute resolution SHOULD
ensure that the caller side and the recipient side each retain the artifact, or
records sufficient to validate and contextualize it, for the applicable audit
period. For example, a downstream agent might bill the presenting agent only
for work that it accepted. In that case, the recipient-signed `hop_ack` helps
both sides later prove exactly which hop, target context, and accepted inbound
artifact are in scope.

`hop_ack` does not by itself prove successful completion or correctness of the
requested operation.

Recipients are not required to issue `hop_ack` for rejected, malformed,
abusive, unauthorized, or rate-limited requests. Absence of `hop_ack` prevents proof of acceptance under this extension.

When a deployment needs `hop_ack` to acknowledge multiple distinct operations
performed under the same inbound token and the same nominal target, it MUST
include a request-unique `request_id` inside `target_context`.

The acknowledgment payload MUST include at least:

* `ctx` = `actor-chain-hop-ack-v1`;
* `acti`;
* `actp`;
* `jti`, a unique identifier for the `hop_ack` JWT itself;
* `inbound_jti`, copied from the acknowledged inbound token;
* OPTIONAL `presenter`, the presenting actor's ActorID when established under
  local policy for that hop;
* `recipient`, the acknowledging recipient's ActorID;
* `target_context`;
* `iat`, a JWT NumericDate recording when the acknowledgment was issued;
* `exp`, a short-lived JWT NumericDate;
* for declared profiles, OPTIONAL inbound `act` when that profile disclosed
  `act` on the acknowledged hop;
* for verified profiles, `inbound_commitment`, the verified inbound
  commitment digest copied directly from the inbound token's `actc.curr`; and
* `ack`, whose value MUST be `accepted`.

A `hop_ack` MUST be signed by the recipient using JWS.

## Receiver Acknowledgment Validation

A caller or coordinating component that receives `hop_ack` and relies on it for
acceptance processing MUST verify at least:

* the JWS signature using the recipient identity and keying material expected by
  local trust policy;
* the JWS protected header contains `typ=act-hop-ack+jwt`;
* `ctx=actor-chain-hop-ack-v1`;
* `acti` equals the actor-chain identifier of the inbound token for which
  acknowledgment is being evaluated;
* `actp` equals the active profile of that inbound token;
* `jti` is unique for the acknowledgment artifact under local replay policy;
* `inbound_jti` equals the `jti` of the inbound token that was actually sent to
  the recipient;
* if `presenter` is present, it equals the presenting actor established under
  local policy for the acknowledged hop;
* `recipient` equals the recipient from which acknowledgment is expected;
* `target_context` equals the exact canonical target context that was
  requested, communicated, or deterministically derived for the acknowledged
  hop;
* `iat` is present and acceptable under local clock policy;
* `exp` has not expired;
* for declared profiles, if `act` is present, the carried `act` equals the
  inbound `act` for the acknowledged hop and MUST NOT disclose more than that
  acknowledged hop disclosed;
* for verified profiles, `inbound_commitment` equals the verified inbound
  commitment digest copied from the inbound token's `actc.curr`; and
* the `ack` member is present and its value equals `accepted`.

When the inbound token being acknowledged was obtained by cross-domain
re-issuance or Refresh-Exchange, the `target_context` compared here is the
exact canonical value for that acknowledged presentation. Any preserved step
proofs and `actc` from an earlier chain-extending hop continue to reflect the
target context of that earlier hop, not a later locally rewritten audience,
unless those values are identical.

# Canonicalization and Commitment Processing {#canonicalization-commitment}

## Canonicalization {#canonicalization}

All profile-defined signed or hashed inputs MUST use a canonical serialization
defined by this specification.

In this version of the specification, `CanonicalEncode(x)` means JCS
[@RFC8785] applied to the JSON value `x`.

`Hash_halg(x)` denotes the raw hash output produced by applying the selected
commitment hash algorithm `halg` to the octet sequence `x`.

`b64url(x)` denotes the base64url encoding of the octet sequence `x` without
trailing padding characters, as defined by [@RFC7515] Appendix C.

Canonical profile-defined proof payloads MUST be serialized using JCS [@RFC8785].

## Commitment Hash Algorithms {#commitment-hash-algorithms}

Proof-bound profiles use a named hash algorithm for construction of
`actc`. Commitment hash algorithm identifiers are values from the IANA Named
Information Hash Algorithm Registry [@RFC6920] [@IANA.Hash.Algorithms].

The following requirements apply:

* `halg` MUST be a text string naming a hash algorithm from the IANA Named
  Information Hash Algorithm Registry.
* Implementations supporting verified profiles MUST implement `sha-256`.
* Implementations SHOULD implement `sha-384`.
* Every `actc` object and every verified profile bootstrap context MUST carry
  an explicit `halg` value. Verifiers MUST NOT infer or substitute `halg` when
  it is absent.
* Verifiers MUST enforce a locally configured allow-list of acceptable
  commitment hash algorithms and MUST NOT accept algorithm substitution based
  solely on attacker-controlled inputs.
* Hash algorithms with truncated outputs, including truncated `sha-256`
  variants, MUST NOT be used with this specification.
* Additional registry values MAY be used only if they are permitted by this
  specification or a future Standards Track update to it, and verifiers MUST
  reject locally deprecated or disallowed algorithms.
* An Authorization Server MUST NOT initiate a new workflow using a locally
  deprecated or disallowed algorithm. Whether an already-issued workflow using
  such an algorithm may continue is a matter of local policy.

## Commitment Function {#commitment-function}

Proof-bound profiles use `actc` to bind each accepted hop to the
prior accepted state. The commitment hash algorithm is selected once for the
workflow by the issuing Authorization Server during bootstrap and remains fixed
for the lifetime of that workflow instance.

Each `actc` value is a signed commitment object whose payload
contains:

* `ctx`: the context string `actor-chain-commitment-v1`. This context string
  identifies the commitment payload version defined by the initial standardized
  version of this specification. During Internet-Draft development before that
  version is standardized, changes to the commitment payload can still be
  incorporated into `-v1`. After the initial standardized version is published,
  any revision that changes commitment payload membership, semantics, or
  canonicalization in a non-compatible way MUST allocate a new version suffix.
  Verifiers MUST reject commitments whose `ctx` value does not exactly match an
  expected, implemented version;
* `iss`: the issuer identifier of the Authorization Server that signs this
  commitment object;
* `acti`: the actor-chain identifier;
* `actp`: the active profile identifier;
* `halg`: the hash algorithm identifier;
* `prev`: the prior commitment digest, or the bootstrap `initial_chain_seed` at
  workflow start;
* `step_hash`: `b64url(Hash_halg(step_proof_bytes))`; and
* `curr`: `b64url(Hash_halg(CanonicalEncode({ctx, iss, acti, actp, halg, prev, step_hash})))`.

The `curr` value MUST be computed over exactly the seven members `ctx`, `iss`,
`acti`, `actp`, `halg`, `prev`, and `step_hash`, excluding `curr` itself. The
resulting digest is then inserted as the transported `curr` member.

Let `prev_digest` denote the prior commitment-state digest for the step being
processed: at bootstrap it is the `initial_chain_seed`, and for later steps it
is the verified `curr` value extracted from the inbound `actc`.
For the JWT binding defined in this version, let `step_proof_bytes` denote the
ASCII bytes of the exact compact JWS string submitted as
`actor_chain_step_proof`.
Let `as_issuer_id` denote the issuer identifier that the Authorization Server
places into the commitment object's `iss` member, typically its issuer value.
The commitment hash therefore binds the transmitted step-proof artifact, not
merely its decoded payload.

Accordingly, `step_hash` and `curr` are commitments to the exact compact-JWS
proof bytes accepted for that hop. Two semantically equivalent decoded proofs
MAY therefore produce different commitment values when their compact-JWS bytes
differ.


When a profile-defined proof input refers to a prior
`actc`, the value incorporated into the proof input MUST be
that prior commitment's verified `curr` digest string, copied directly from the
validated `actc` payload, not the raw serialized commitment object.

The abstract function used throughout this document is therefore:

~~~ text
Commit_AS(as_issuer_id, acti, actp, prev_digest, step_proof_bytes, halg)
  = Authorization-Server-signed commitment object over payload {
      ctx,
      iss,
      acti,
      actp,
      halg,
      prev = prev_digest,
      step_hash = b64url(Hash_halg(step_proof_bytes)),
      curr = b64url(Hash_halg(CanonicalEncode({ctx, iss, acti, actp, halg, prev, step_hash})))
    }
~~~

The exact wire encoding of the signed commitment object is defined in {{jwt-jws-binding}}.

In calls to `Commit_AS`, the `iss` input is the issuer identifier of the
Authorization Server signing the new commitment object, and `acti` and `actp`
are the workflow and profile values being preserved for that workflow state.

# Artifact Typing {#artifact-typing}

## JWT Artifact Types

JWT-based artifacts defined by this specification MUST use explicit `typ`
values.

The following JWT `typ` values are defined:

* `act-step-proof+jwt`
* `act-commitment+jwt`
* `act-hop-ack+jwt`

Verifiers MUST enforce mutually exclusive validation rules based on artifact
type and MUST NOT accept one artifact type in place of another. They MUST verify
the expected JWT `typ`, exact `ctx` value where applicable, and
artifact-specific payload structure defined by the relevant binding section of
this specification.

`typ` matching for profile-defined artifacts MUST be exact string equality,
without case folding, prefix matching, or media-type alias mapping. Missing or
unexpected `typ` values MUST cause rejection of the artifact for that
processing path.

If a JOSE protected header contains `crit`, verifiers MUST reject unless every
listed header parameter is understood and processed according to its
specification. This document defines no profile-specific use of unencoded JWS
payloads; profile-defined artifacts in this version therefore use the ordinary
base64url-encoded JWS payload form.

# Common Security and Enforcement Requirements {#security-enforcement}

This section collects enforcement requirements that all profiles rely on but
that need not be read before the main profile flows. Implementations still
MUST satisfy these requirements even when they are consulted later in a first
reading pass.

## JOSE and Parser Hardening

Implementations validating profiled access tokens, step proofs, `hop_ack`, and
`actc` MUST apply strict JOSE and JSON parsing behavior to avoid
implementation-differential acceptance.

At minimum, validators MUST:

* reject duplicate member names in any JSON object that contributes to
  profile-defined validation, signature verification, canonicalization, or
  commitment inputs;
* reject malformed compact JWS syntax, including malformed base64url segments;
* reject unsupported critical JOSE headers as defined in {{artifact-typing}} and
  {{jwt-jws-binding}};
* enforce exact expected claim types for profile-defined claims before
  semantic processing (for example, `actp`, `acti`, `iss`, `sub`, and `jti`
  as strings; `target_context` as an object where required by this
  specification; and `actc` as a compact JWS string when required);
* treat type mismatch as a profile-validation failure; and
* for verified profiles, treat missing `actc` as a profile-validation failure.

## Actor Authentication and Presenter Binding {#actor-authentication}

This specification does not define or require any particular actor-
authentication, presenter-binding, or token-binding mechanism. Authorization
Servers and recipients MAY establish current-actor or presenting-actor identity
using any locally trusted method. Recipient authorization policy based on such
inputs is outside the scope of this specification.

When deployment policy depends on a specific presenter-binding or token-binding
mechanism class (for example mTLS-anchored or DPoP-anchored processing), that
mechanism class MUST be fixed by local policy or a companion profile and MUST
NOT be inferred from actor-chain artifacts alone.

## Actor and Recipient Proof Keys {#proof-keys}

For verified profiles and for `hop_ack`, any signature used as a
profile-defined proof MUST be generated with an asymmetric key whose
verification material is trusted under local policy for the actor or recipient
identity represented in that artifact.

For a verified profile step proof, the ActorID represented in the proof and the
key used to sign the proof MUST be bound to the same actor identity under local
trust policy. The Authorization Server MUST verify the proof using trusted
verification material for that actor identity before accepting the proof.

For `hop_ack`, the recipient ActorID and the key used to sign the acknowledgment
MUST likewise be bound to the same recipient identity under local trust policy.
If `presenter` is included in a `hop_ack`, that value MUST be established under
local policy and MUST NOT expand disclosure beyond the selected profile.

Shared client secrets MUST NOT be the sole basis for independently verifiable
step proofs or receiver acknowledgments.

Deployments that rely on later verification of archived step proofs or
acknowledgments MUST retain, or be able to recover, the verification material
and identity-binding records needed to validate those signatures during the
applicable audit period. Deployments that claim verified-profile auditability
beyond Authorization-Server-only trust SHOULD also retain, or be able to
recover, the exact compact JWS step-proof artifacts and their associated
workflow context for the applicable audit period, because commitment digests
alone do not prove which actor signed which hop.

## Intended Recipient Validation {#intended-recipient}

When a current actor submits an inbound token as a `subject_token` in token
exchange, the accepting Authorization Server MUST normally verify that the
authenticated current actor was an intended recipient of that inbound token
according to local audience, resource, or equivalent validation rules. For
`actor_chain_refresh=true` and `actor_chain_cross_domain=true`, this intended-
recipient check does not apply in the same way because the exchange preserves
rather than extends previously accepted chain state. The Authorization Server
MUST instead apply the preserve-state actor-establishment rule in
{{preserve-state-exchanges}}.

Possession of an inbound token alone is insufficient.

## Replay and Freshness {#replay-freshness}

Recipients and Authorization Servers MUST enforce replay and freshness checks on
inbound tokens according to local policy.

For profiles that use actor-signed step proofs, the accepting Authorization
Server:

* MUST detect replay of a previously accepted step proof within its
  replay-retention window;
* MUST treat an exact replay of a previously accepted compact-JWS step proof
  for the same authenticated actor and same prior state as an idempotent retry,
  not as a distinct successor;
* MUST, for such an idempotent retry, return the previously accepted
  successor state, or an equivalent token representing that same accepted
  successor state, while any required retry record is retained;
* SHOULD, during that retry-retention window, retain the exact previously
  issued response or otherwise ensure that a retried response carries the same
  accepted chain state, because recomputing with probabilistic signatures can
  change wire bytes even when the decoded accepted state is equivalent; and
* MUST reject a different attempted successor for the same
  `(acti, prior_state, target_context)` tuple unless local policy explicitly
  authorizes replacement or supersession; this base specification does not
  standardize how multiple accepted successors that share earlier history are
  correlated or later merged. Deployments that expect multiple distinct
  same-target successors SHOULD distinguish them by including a unique
  `request_id` in `target_context`.

## Chain Depth Limits {#chain-depth-limits}

Authorization Servers MUST enforce a configurable maximum chain depth for
accepted workflow state. A RECOMMENDED default is 10 entries.

A token exchange that would cause the accepted chain depth to exceed the
Authorization Server's configured maximum MUST be rejected with `invalid_grant`.

Recipients MAY enforce stricter local limits on disclosed actor-chain depth. A
recipient that receives an inbound token whose disclosed actor chain exceeds
its configured maximum MUST treat that condition as a profile-validation
failure.

Error responses and logs MUST NOT disclose actor identities beyond what the
selected profile permits.

# Authorization Server Metadata {#as-metadata}

Actor-chain capability discovery uses OAuth 2.0 Authorization Server Metadata
[@RFC8414]. This specification does not define a new discovery endpoint.
Clients retrieve Authorization Server metadata from the RFC 8414 well-known
metadata endpoint derived from the issuer, verify that the returned `issuer`
matches the configured issuer, and then process the actor-chain-specific
metadata values defined below.

An Authorization Server supporting this specification SHOULD publish metadata
describing its supported actor-chain capabilities.

This specification defines the following Authorization Server metadata values:

* `actor_chain_bootstrap_endpoint`:
  URL of the Authorization Server endpoint used to mint verified profile
  bootstrap context for initial actors;
* `actor_chain_profiles_supported`:
  array of supported actor-chain profile identifiers. Each value MUST be the
  exact identifier string used both as the `actor_chain_profile` token request
  parameter value and as the `actp` token claim value;
* `actor_chain_commitment_hashes_supported`:
  array of supported commitment hash algorithm identifiers;
* `actor_chain_receiver_ack_supported`:
  boolean indicating whether the Authorization Server supports processing and
  policy for `hop_ack`;
* `actor_chain_refresh_supported`:
  boolean indicating whether the Authorization Server supports Refresh-Exchange
  processing under this specification; and
* `actor_chain_cross_domain_supported`:
  boolean indicating whether the Authorization Server supports cross-domain
  re-issuance processing under this specification.

Client behavior is:

1. obtain or configure the Authorization Server issuer;
2. fetch RFC 8414 metadata from the corresponding well-known endpoint;
3. verify the returned `issuer` exactly matches the configured issuer;
4. check `actor_chain_profiles_supported` and any other needed actor-chain
   capability fields; and
5. fail closed if the required profile or capability is absent, unless local
   policy explicitly allows fallback to plain RFC 8693 behavior.

If omitted, clients MUST NOT assume support for any actor-chain profile beyond
out-of-band agreement.

# Error Handling {#error-handling}

Token exchange errors in this specification build on OAuth 2.0 and OAuth 2.0
Token Exchange.

An Authorization Server processing a token exchange request applies the
following mapping:

| OAuth error code | Actor-chain failure class |
| --- | --- |
| `invalid_request` | Malformed request, unsupported profile binding, conflicting preserve-state parameters, or structurally malformed profile-defined input. |
| `invalid_target` | Requested audience, recipient, resource, or canonical target context is not permitted or not supported. |
| `invalid_grant` | Subject-token, continuity, proof, replay, disclosure, or preserve-state validation failed. |

`invalid_request` includes malformed or missing profile-defined parameters,
malformed bootstrap context, malformed ActorID values, malformed commitment
objects, unsupported profile bindings, both `actor_chain_cross_domain=true` and
`actor_chain_refresh=true`, and structurally malformed inline `act`.

`invalid_target` includes cases in which the requested audience, canonical
target context, or recipient is not permitted or not supported, a
Refresh-Exchange attempts to retarget to a different recipient, no unique
logical chain-extending recipient can be determined, or a cross-domain
`target_context` member cannot be preserved or mapped safely.

`invalid_grant` includes failures such as:

* failed `subject_token` validation;
* intended-recipient failure;
* actor-chain continuity failure at token exchange;
* replay or freshness failure;
* `actor_chain_step_proof` verification failure;
* bootstrap-context reuse that is neither an idempotent retry nor an authorized
  distinct initial successor;
* required inline `act` disclosure absent;
* profile-disclosure rule failure;
* verified step-proof target context inconsistent with the accepted target
  context;
* issued token target authority would be broader than the proof-bound target
  context;
* preserve-state authorization policy failure;
* represented current actor for preserve-state exchange could not be
  established or was not authorized for the requester;
* submitted prior state inconsistent with the claimed profile state; and
* actor-chain depth limit exceeded.

Implementations SHOULD provide additional machine-readable or human-readable
diagnostics that distinguish actor-chain-specific failure classes that map to
the same base OAuth error code. Such diagnostics are for troubleshooting and
interoperability support only and MUST NOT alter the base OAuth error value
required by this specification. Examples include diagnostics indicating replay
detection, intended-recipient failure, step-proof verification failure,
profile-disclosure failure, or preserved-state inconsistency.

Recipients and Authorization Servers MUST return protocol-appropriate error
signals for authentication, authorization, profile-validation, and continuity
failures. When the selected profile requires inline `act` disclosure for an
artifact, omission of `act`, or presence of an `act` value that fails that
profile's disclosure rules, MUST be treated as a profile-validation failure.

In HTTP deployments, this typically maps to 400-series status codes and
OAuth-appropriate error values. In non-HTTP deployments, functionally
equivalent protocol-native error signaling MUST be used.

Error responses and logs MUST NOT disclose undisclosed prior actors, full step
proofs, canonical proof inputs, or other sensitive proof material unless the
deployment explicitly requires such disclosure for diagnostics.

When deployments provide `error_description`, `error_uri`, logs, or similar
diagnostics for actor-chain failures, they SHOULD distinguish among underlying
failure causes where doing so does not disclose hidden actors, full proofs, or
other sensitive material.

# JWT / JWS Binding {#jwt-jws-binding}

This section defines the JWT and JWS wire representation for profile-defined
ActorID values, disclosed `act` structures, step proofs, receiver
acknowledgments, and commitment objects.

## ActorID in JWT

An ActorID is a JSON object with exactly two members:

* `iss`: a string containing the issuer identifier; and
* `sub`: a string containing the subject identifier.

The object MUST be serialized using JCS [@RFC8785] whenever it is included in
profile-defined proof or commitment inputs.

When `actp` is present, the disclosed `act` structure in a JWT is an
ActorChainNode. Newly issued profile-defined nodes MUST contain explicit
`iss` and `sub`, and MAY contain a nested `act` member whose value is the
immediately prior disclosed ActorChainNode. Validators MUST also be able to
normalize a validated inbound node that omits `iss` and inherits the enclosing
issuer context.

## Step Proof in JWT {#jwt-step-proof}

The `actor_chain_step_proof` token request parameter value MUST be a compact JWS
string [@RFC7515]. The JWS protected header MUST contain `typ=act-step-proof+jwt`. The
JWS payload MUST be the UTF-8 encoding of a JCS-serialized JSON object.

Verifiers MUST require exact `typ=act-step-proof+jwt` matching for this
artifact class. The `alg` header parameter MUST be present and MUST identify
an asymmetric signature algorithm accepted by local policy. Algorithm
identifiers are defined by JSON Web Algorithms (JWA) [@RFC7518] or by an
applicable extension. `alg=none` MUST NOT be accepted. If `crit` is present,
verifiers MUST reject unless every listed parameter is understood and
processed.

For all profiles in the verified branch, the payload MUST contain:

* `ctx`;
* `acti`;
* `prev`;
* `sub`;
* `target_context`;
* `act`; and
* `iat`, a JWT NumericDate recording when the step proof was signed.

When this payload is used as commitment input through `step_hash`, the
`step_proof_bytes` value is the ASCII byte sequence of the exact compact JWS
serialization of the proof artifact.

The `ctx` member value MUST equal the profile-specific step-proof
domain-separation string `ds(profile)` defined in
{{verified-common-processing}}. The `prev` member MUST be the base64url string
value of the prior commitment digest or bootstrap seed, copied directly from
the verified inbound `actc.curr` or bootstrap response, respectively. The
`sub` member MUST be the exact preserved workflow `sub` string for the
same-domain hop being extended. The `act` member MUST be an ActorChainNode
structure and denotes the profile-defined verified actor-visible chain for the
hop. For the Verified Subset Disclosure profile, the returned profiled access
token `act` MAY disclose any ordered subsequence of that verified chain that
disclosure policy permits, or MAY omit `act` entirely when that profile and
local policy permit omission. For the Verified Actor-Only Disclosure profile,
the returned profiled access token `act` MUST contain only the outermost
current actor. The `target_context` member MUST conform to the representation
defined in {{target-context}}. The `iat` value MUST be a JWT NumericDate.

The accepting Authorization Server MUST reject a step proof whose `iat` is
outside a locally configured acceptance window relative to the Authorization
Server's clock. The acceptance window SHOULD be small, typically on the order
of 60 seconds, unless local clock discipline justifies a tighter bound or a
wider bound is explicitly authorized for the workflow. Replay handling under
{{replay-freshness}} continues to apply independently of `iat`.

The JWS algorithm MUST be an asymmetric algorithm. The `none` algorithm MUST
NOT be used. The JWS verification key MUST be trusted under local policy for
the ActorID represented in the proof.

## Receiver Acknowledgment in JWT {#jwt-hop-ack}

A `hop_ack`, when used in a JWT deployment, MUST be a compact JWS string [@RFC7515]. The
JWS protected header MUST contain `typ=act-hop-ack+jwt`. The JWS payload MUST
be the UTF-8 encoding of a JCS-serialized JSON object with at least these
members:

Verifiers MUST require exact `typ=act-hop-ack+jwt` matching for this artifact
class. The `alg` header parameter MUST be present and MUST identify an
asymmetric signature algorithm accepted by local policy. Algorithm identifiers
are defined by JWA [@RFC7518] or by an applicable extension. `alg=none` MUST
NOT be accepted. If `crit` is present, verifiers MUST reject unless every listed
parameter is understood and processed.

* `ctx`;
* `acti`;
* `actp`;
* `jti`;
* `inbound_jti`;
* `iat`;
* `exp`;
* `target_context`;
* OPTIONAL `presenter`;
* `recipient`;
* for declared profiles, OPTIONAL `act` as permitted by the selected profile's
  disclosure rules for the acknowledged inbound hop;
* for verified profiles, `inbound_commitment`; and
* `ack`.

The `ctx` member value MUST equal `actor-chain-hop-ack-v1`. The
`recipient` member MUST be an ActorID object. If `presenter` is present, it
MUST be an ActorID object established under local policy for that hop. The
`ack` member MUST have the value `accepted`. The `jti` member MUST uniquely
identify the `hop_ack` JWT itself. The `inbound_jti` member MUST carry the
`jti` value from the acknowledged inbound token. The `iat` and `exp` members
MUST be JWT NumericDate values, and `exp` SHOULD be short-lived according to
local policy. The `target_context` member MUST conform to the representation
defined in {{target-context}}. For declared profiles, the `act`
member, when present, MUST carry the validated inbound `act` value and
MUST NOT disclose more than the selected profile allowed on the acknowledged
inbound hop. For verified profiles, the `inbound_commitment` member MUST be
copied directly from the verified inbound commitment digest extracted from the
inbound token's `actc.curr`. The JWS signer MUST be the recipient, and the
verification key MUST be trusted under local policy for that recipient
ActorID.

## Commitment Object in JWT {#jwt-commitment}

The `actc` claim value MUST be a compact JWS string [@RFC7515]. The JWS
protected header MUST contain `typ=act-commitment+jwt`.

Verifiers MUST require exact `typ=act-commitment+jwt` matching for this
artifact class. The `alg` header parameter MUST be present and MUST identify
an asymmetric signature algorithm accepted by local policy. Algorithm
identifiers are defined by JWA [@RFC7518] or by an applicable extension.
`alg=none` MUST NOT be accepted. If `crit` is present, verifiers MUST reject unless every
listed parameter is understood and processed.

The JWS payload MUST be the UTF-8 encoding of a JCS-serialized JSON object with
exactly these members:

* `ctx`;
* `iss`;
* `acti`;
* `actp`;
* `halg`;
* `prev`;
* `step_hash`; and
* `curr`.

The meaning of those members is defined in the main text. `actc` is a
commitment-ledger artifact, not an access token, and therefore does not use
access-token lifetime claims such as `exp`.

# Security Considerations {#security-considerations}

A fuller threat discussion appears in {{threat-model}}. This section keeps only the
security considerations that directly affect interoperable processing or likely
implementation choices.

## Actor Authentication and Presenter Binding Are Deployment-Specific

This specification assumes that Authorization Servers can determine the current
actor for an exchange and that recipients MAY establish the presenting actor for
a hop under local policy when needed. The mechanisms that provide those inputs
are intentionally outside the scope of this specification.

## Canonicalization Errors Break Interoperability and Proof Validity

Any ambiguity in canonical serialization, actor identity representation, target
representation, or proof payload encoding can cause false verification failures
or inconsistent commitment values across implementations.

## Target Consistency Is a Security Boundary

For verified profiles, the proof-bound target context, accepted Authorization
Server state, and issued access-token authority are one consistency boundary.
Implementations must fail closed if these values cannot be shown to be
identical or properly narrowed.

## Commitment State Is Byte-Oriented

For JWT bindings in this specification, commitment linkage uses the exact
compact-JWS proof artifact bytes. This means commitment state is intentionally
artifact-byte-oriented rather than normalized to semantic proof meaning.
Implementations MUST NOT assume semantically equivalent decoded proofs will
yield identical `step_hash` or `curr` values unless the underlying compact-JWS
bytes are also identical. Parties that need semantic or evidentiary replay
SHOULD log and retain those exact proof artifacts and verification context.

## Disclosed Chain Does Not Prevent Payload Abuse

A valid disclosed actor chain does not imply that the application-layer request
content is safe, correct, or policy-conformant. Recipients MUST apply local
payload validation and authorization.

## Verified Profiles Depend on Proof Retention

The evidentiary benefits of the verified profiles depend on retention or
recoverability of step proofs, exchange records, and relevant verification
material. Without such retention, the profiles still provide structured
commitment state, but post hoc provability and non-repudiation are materially
weakened.

Authorization Servers supporting verified profiles SHOULD retain proof state,
exchange records, authoritative workflow chain state, and the historical
verification material needed for later verification for at least the maximum
validity period of the longest-lived relevant token plus a
deployment-configured audit window. Retention policies SHOULD also account for
later verification during or after key rotation.

## Subset-Disclosure Profiles Reveal Only a Verified Subset

Recipients using the subset-disclosure profiles can authorize based only on the
disclosed actor chain subset that they verify. They MUST treat undisclosed
prior actors as unavailable and MUST NOT infer adjacency, absence, or exact
chain length from the disclosed subset alone.

In this base JWT/JWS binding, the returned profiled access token is visible to the
current actor and to the next recipient. Therefore, a returned subset-disclosure
token cannot safely reveal an actor identity that the current actor is not
permitted to learn. A future recipient-protected disclosure mechanism MAY relax
that limitation, but it is outside this base specification.

A singleton disclosed actor chain containing only the current actor is a valid
subset-disclosure outcome. In that case, downstream authorization is current-
actor-only even though the underlying profile remains one of the subset
profiles unless `actp` explicitly selects an actor-only profile.

Deployments whose recipient authorization requires prior-path membership or
ordering evidence MUST ensure that the selected profile and disclosure policy
expose that required evidence. They MUST NOT treat actor-only or omitted-`act`
outcomes as sufficient for such path-sensitive authorization.

## Cross-Domain Re-Issuance Must Preserve Chain State

A cross-domain Authorization Server that re-issues a local token for the next
recipient must preserve the relevant disclosed actor-chain state and must not
broaden target authority. For `sub`, it can translate the representation only
when doing so preserves the same underlying subject semantics and does not
broaden disclosure. Unknown target-context members are not safe to ignore; they
are either preserved with constraining semantics, mapped safely, or rejected.

## Branch Reconstruction Is an Audit Concern

This specification allows an Authorization Server to issue multiple successor
tokens from one prior accepted state, but it does not standardize merge or
sibling-discovery semantics across branches. Reconstructing a branched call
graph is therefore a forensic or legal-audit concern rather than a normal
online authorization requirement.

Retained Authorization Server records, timestamps, commitment state, and causal
links among presenting actors, current actors, and subsequent actors can often
reveal much of the effective call graph, but this base specification alone does
not guarantee a complete standardized graph across all branches.

This specification does not standardize per-actor causal timestamps inside
nested `act`. Deployments that need branch and time reconstruction SHOULD rely
on retained Authorization Server records, profiled access token or proof timestamps,
commitment state, and parent-child causal linkage across accepted successor
tokens rather than embedding chronology fields in disclosed `act` entries.

## Intended Recipient Checks Reduce Confused-Deputy Risk

Accepting Authorization Servers MUST ensure that the authenticated current actor
was an intended recipient of the inbound `subject_token`. This reduces a class
of deputy and repurposing attacks, though it does not eliminate all
confused-deputy scenarios.

## Chain Depth

Chain-depth limits reduce resource-exhaustion risk and keep disclosed actor
chains understandable to recipients. The deterministic processing and error
mapping for chain-depth enforcement are defined in {{chain-depth-limits}}.

## Key Management

Actors SHOULD use short-lived keys and/or hardware-protected keys. Deployments
that require long-term auditability MUST retain, or make durably discoverable,
the historical verification material needed to validate archived step proofs and
receiver acknowledgments after key rotation.

# Privacy Requirements and Considerations {#privacy}

This section keeps the privacy requirements that affect protocol behavior.
Additional trust-boundary and operational notes appear in {{trust-audit}}.

Profiles that disclose prior actors inline expose those actors to downstream
recipients. Deployments that do not require full disclosed prior-actor
authorization SHOULD consider one of the subset-disclosure profiles.

The stable actor-chain identifier `acti` correlates all accepted hops within one
workflow instance. Accordingly, `acti` MUST be opaque and MUST NOT encode actor
identity, profile selection, business semantics, or target meaning.

Even in the privacy-preserving profiles, the Authorization Server
processing token exchange observes the authenticated current actor and any
retained chain-related state. Accordingly, these profiles reduce profiled
access token disclosure but do not hide prior actors from the issuing
Authorization Server.

Deployments concerned with minimization SHOULD consider:

* pairwise or pseudonymous actor identifiers;
* workflow-local or pairwise `sub` aliases;
* omission of auxiliary claims unless receiving policy depends on them; and
* the subset-disclosure profiles when partial actor-chain disclosure is
  sufficient.

## Subset Disclosure and Auxiliary Encodings

This specification defines subset-disclosure semantics for the Declared
Subset Disclosure profile and the Verified Subset Disclosure profile. In
both profiles, if `act` is disclosed, the recipient-visible `act` is a
profile-defined ordered subsequence of the actor chain for that hop, carried as
a disclosed `act` claim containing only the disclosed subset. A subset
profile MAY also omit `act` entirely.

When a subset profile discloses `act`, that representation is the interoperable
base-wire format for the disclosed subset.

Deployments MAY additionally use an optional selective-disclosure or
recipient-protected encoding technique by agreement, including Selective
Disclosure JWT (SD-JWT) [@RFC9901], a future COSE/CBOR companion binding,
or an encrypted envelope, but only as an auxiliary overlay. Such an overlay
MUST NOT replace any required disclosed-subset `act` representation in the
interoperable base-wire format; it MAY only add an equivalent presentation form
whose disclosed value matches the same recipient-visible `act` and does not
change any required validation result.

This specification defines the following actor-chain-specific constraints on
such use:

* for the Declared Subset Disclosure profile, any disclosed actor chain MUST
  be an ordered subsequence of the asserted chain state for that hop;
* for the Verified Subset Disclosure profile, any disclosed actor chain MUST
  be an ordered subsequence of the verified actor-visible chain for that
  hop;
* if the selected profile uses step proofs or chain commitments, those
  artifacts remain bound to the verified hop progression, not to a later
  disclosed subset;
* a verifier MUST treat undisclosed information as unavailable and MUST require
  disclosure of any information needed for authorization; and
* an encoding used with a Full Disclosure profile MUST reveal the complete
  disclosed actor chain required by that profile to the recipient before
  authorization.

# IANA Considerations {#iana}

This specification does not create a new hash-algorithm registry.
`actc` uses hash algorithm names from the IANA Named
Information Hash Algorithm Registry [@IANA.Hash.Algorithms], subject to the
algorithm restrictions defined in this document.

## JSON Web Token Claims Registration

This document requests registration of the following claims in the "JSON Web
Token Claims" registry established by [@RFC7519]:

| Claim Name | Claim Description | Change Controller | Specification Document(s) |
| --- | --- | --- | --- |
| `actc` | Proof-bound chain state binding accepted hop progression for the active profile. | IETF | [this document] |
| `acti` | Actor-chain identifier preserved across accepted hops. | IETF | [this document] |
| `actp` | Actor-chain profile identifier for the issued token. | IETF | [this document] |

## Media Type Registration

This document requests registration of the following media types in the
"Media Types" registry established by [@RFC6838]:

| Type | Subtype | Application |
| --- | --- | --- |
| `application` | `act-step-proof+jwt` | OAuth 2.0 Token Exchange actor-chain step proofs. |
| `application` | `act-commitment+jwt` | OAuth 2.0 Token Exchange actor-chain commitments. |
| `application` | `act-hop-ack+jwt` | OAuth 2.0 Token Exchange actor-chain receiver acknowledgments. |

The following registration fields apply to each media type above:

* Required parameters: N/A
* Optional parameters: N/A
* Encoding considerations: binary
* Security considerations: see this document
* Interoperability considerations: N/A
* Published specification: this document
* Fragment identifier considerations: N/A
* Additional information: Magic Number(s): N/A; File Extension(s): N/A;
  Macintosh File Type Code(s): N/A
* Contact: IETF
* Intended usage: COMMON
* Restrictions on usage: N/A
* Author: IETF
* Change controller: IETF

## OAuth URI Registration

This document requests registration of the following value in the
"OAuth URI" registry established by [@RFC6749]:

| URI | Description | Change Controller | Specification Document(s) |
| --- | --- | --- | --- |
| `urn:ietf:params:oauth:grant-type:actor-chain-bootstrap` | OAuth grant type for the initial verified profile bootstrap token request. | IETF | [this document] |

## OAuth Authorization Server Metadata Registration

This document requests registration of the following metadata names in the
"OAuth Authorization Server Metadata" registry established by [@RFC8414]:

| Metadata Name | Metadata Description | Change Controller | Specification Document(s) |
| --- | --- | --- | --- |
| `actor_chain_bootstrap_endpoint` | Endpoint used to mint bootstrap context for verified profile initial actors. | IETF | [this document] |
| `actor_chain_profiles_supported` | Supported actor-chain profile identifiers. | IETF | [this document] |
| `actor_chain_commitment_hashes_supported` | Supported commitment hash algorithm identifiers. | IETF | [this document] |
| `actor_chain_receiver_ack_supported` | Indicates support for receiver acknowledgments (`hop_ack`) under this specification. | IETF | [this document] |
| `actor_chain_refresh_supported` | Indicates support for Refresh-Exchange under this specification. | IETF | [this document] |
| `actor_chain_cross_domain_supported` | Indicates support for cross-domain re-issuance under this specification. | IETF | [this document] |

## OAuth Parameter Registration

This document requests registration of the following parameter names in the
relevant OAuth parameter registry:

| Parameter Name | Parameter Usage Location | Change Controller | Specification Document(s) |
| --- | --- | --- | --- |
| `actor_chain_profile` | actor-chain bootstrap endpoint request; OAuth token endpoint request | IETF | [this document] |
| `actor_chain_bootstrap_context` | actor-chain bootstrap endpoint response; OAuth token endpoint request | IETF | [this document] |
| `actor_chain_step_proof` | OAuth token endpoint request | IETF | [this document] |
| `actor_chain_refresh` | OAuth token endpoint request | IETF | [this document] |
| `actor_chain_cross_domain` | OAuth token endpoint request | IETF | [this document] |

Part III is informative and defines no conformance requirements. Where Part III
summarizes requirements from Part II, Part II controls.

This part is organized so that it could be separated into an Informational
companion draft in a future revision.

# Motivating Real-World Examples

## Full Disclosure: Emergency Production Change in Critical Infrastructure

A safety-critical production environment requires a hotfix during an incident.
The workflow is:

* `A` = on-call engineer;
* `B` = incident commander;
* `C` = security approver;
* `D` = deployment service; and
* `E` = runtime control plane.

Every downstream hop must see the complete disclosed approval path before
allowing the change to proceed. The deployment service and runtime control
plane both need to verify inline that the on-call engineer initiated the
action, the incident commander approved it, and the security approver signed
off. This is the motivating case for the Full Disclosure profiles: every hop
needs the same complete disclosed lineage for normal online authorization.

## Subset Disclosure: Regulated M&A Review

A large acquisition review passes through multiple highly sensitive business
functions. The workflow is:

* `A` = market-intelligence team;
* `B` = product-strategy review;
* `C` = internal legal review;
* `D` = antitrust counsel; and
* `E` = Chief Executive Officer.

Intermediate actors are intentionally compartmentalized and may be forbidden
from learning who else contributed to the decision. The CEO, however, may need
a richer disclosed chain before approving the transaction. This is the
motivating case for the Subset Disclosure profiles: the Authorization Server
retains authoritative workflow state and discloses to each recipient only the
portion of the chain that recipient is allowed to learn.

## Actor-Only Disclosure: Bank Wire-Payment Processing Pipeline

A bank processes high-value wire payments through a sequence of narrowly scoped
control services. The workflow is:

* `A` = payment-initiation service;
* `B` = sanctions-screening service;
* `C` = fraud-scoring service;
* `D` = treasury and limit-check service;
* `E` = payment-release service; and
* `F` = SWIFT or bank-connector service.

Each stage authorizes only on the immediately preceding actor for that hop.
The sanctions service needs to know only that the payment-initiation service
invoked it; the fraud service needs to know only that sanctions invoked it;
and so on. Revealing the entire upstream pipeline to every stage adds no value
to the local authorization decision and unnecessarily exposes internal control
topology. This is the motivating case for the Actor-Only profiles: every hop
sees only the current actor inline, while richer workflow state may still be
retained by the Authorization Server for forensic review, legal audit, or
incident review.

# Deployment Context {#deployment-context}

[@RFC8693] defines the top-level `act` claim for the current actor and allows
nested prior actors. However, prior nested `act` claims are informational only
for access-control decisions. In multi-hop systems, especially
service-to-service and agentic systems, that is not sufficient.

Consider:

~~~ text
User -> Orchestrator -> Planner -> Tool Agent -> Data API
~~~

By the time the request reaches the Data API, the immediate caller may or
may not be visible in the token, and the upstream delegation path is not
standardized as a policy input
and is not bound across successive token exchanges in a way that can be
independently validated or audited. This creates several concrete gaps:

* downstream policy cannot reliably evaluate the full delegation path;
* cross-exchange continuity is not standardized;
* tampering by an actor and its home Authorization Server is not uniformly addressed;
* forensic verification of per-hop participation is not standardized; and
* profiled access tokens may disclose more actor-chain information than some
  deployments are willing to reveal.

## When an Actor-Chain Profile Is Needed

Not every OAuth deployment requires an actor-chain profile. The need depends on
whether parties other than the issuing Authorization Server need to reason
about, authorize on, or later prove the actor progression of a multi-hop
workflow.

Plain OAuth 2.0 Token Exchange without this profile family can be sufficient
when all participating components remain within one trust domain and one
Authorization Server, recipients authorize only on the immediate access token,
there is no later need to prove per-hop participation for audit or dispute
resolution, and local conventions for any nested `act` use are self-consistent
across the participating implementations. In that case, adding `actp`, `acti`,
or `actc` adds wire and processing overhead without a clear consumer.

Within one trust domain, an actor-chain profile becomes useful when recipients
need standardized workflow continuity, when multi-step services or agents need
downstream authorization based on actor progression, when approval paths or
privileged actions need later review, when compartmentalized workflows need
recipient-specific disclosure, or when incident review or chargeback processes
need reconstruction of who acted and in what order.

The disclosure mode follows recipient need-to-know. A recipient that needs the
complete disclosed path points toward a Full Disclosure profile. A recipient
that needs only an Authorization-Server-selected subset points toward a Subset
Disclosure profile. A recipient that needs only the immediate upstream actor
points toward an Actor-Only Disclosure profile.

The evidence model follows audit and non-repudiation needs. Declared variants
fit deployments where the issuing Authorization Server is the sole trust anchor
and the non-collusion assumption between an actor and its home Authorization
Server is acceptable. Verified variants add actor-signed step proofs and
cumulative commitment state in `actc` so that later participants and auditors
can verify accepted hop progression with less reliance on Authorization-Server
assertion alone.

Across trust domains, verified profiles are often useful because preserved
`actc` carries cumulative commitment state forward across Authorization Server
boundaries. Cross-domain hops that preserve, rather than extend, accepted chain
state use the cross-domain re-issuance flow defined in
{{cross-domain-reissuance}} and do not append the foreign Authorization Server
to the chain. Disclosure mode remains a per-recipient policy decision at the
issuing or re-issuing Authorization Server.

Action sensitivity can further influence configuration. Higher-impact reads,
state-changing actions, actor-spawning actions, and recursive orchestration can
justify a verified profile, `hop_ack`, `request_id` in `target_context`,
stricter chain-depth limits, stronger retention, and presenter binding.
Action sensitivity does not change the six profiles; it guides how the selected
profile is configured and when stronger evidence is warranted.

In summary, if no party outside the issuing Authorization Server needs to
reason about actor progression, an actor-chain profile is usually not needed.
Otherwise, the disclosure mode is selected by what each recipient is permitted
to learn, and the evidence model is selected by whether later independent proof
of per-hop participation is required. Multi-domain deployments often use a
verified profile together with cross-domain re-issuance. Action sensitivity can
further influence whether hop acknowledgments, request identifiers, stricter
chain-depth limits, and presenter binding are appropriate.

# Threat Model {#threat-model}

This specification defines a multi-hop, multi-actor delegation model across one
or more trust domains. The security properties provided depend on the selected
profile, the trust relationship among participating Authorization Servers,
and the availability of step proofs or exchange records where relied upon.

## Assets

The protocol seeks to protect the following assets:

* continuity of the delegation path;
* integrity of prior-actor ordering and membership;
* continuity of the actor represented as current for each hop when such
  continuity is disclosed or otherwise established under local policy;
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
* the authenticated actor identity used in token exchange is bound under
  local trust policy to the actor identity represented in profile-defined
  proofs; and
* deployments that rely on later proof verification retain, or can discover,
  the verification material needed to validate archived step proofs and exchange
  records.

## Security Goals

The protocol aims to provide the following properties:

* in the Declared Full Disclosure profile, silent insertion, removal,
  reordering, or modification of prior actors is prevented under the assumption
  that an actor does not collude with its home Authorization Server;
* in the Declared Subset Disclosure profile, profiled access tokens reveal
  only a disclosed ordered subset of actors selected by the Authorization
  Server, and authorization is limited to that disclosed subset;
* in the Verified Subset Disclosure profile, each
  accepted hop is bound to an actor-signed proof over the exact actor-visible
  chain for that hop and to cumulative commitment state, while profiled access tokens
  reveal only an ordered subset of that actor-visible chain selected by the
  Authorization Server;
* in the Verified Full Disclosure profile, the actor-visible chain equals the
  complete disclosed actor chain at each hop, preserving complete disclosed-chain authorization while
  improving detectability, provability, and non-repudiation; and
* in the Verified Actor-Only Disclosure profile, profiled access tokens disclose
  only the current actor while preserving current-actor continuity where that
  continuity is disclosed or otherwise established under local policy,
  together with cumulative commitment state for later verification.

## Non-Goals

This specification does not by itself provide:

* integrity or safety guarantees for application payload content;
* complete prevention of confused-deputy behavior;
* concealment of prior actors from the Authorization Server that processes
  token exchange;
* standardized merge or branch-selection semantics across branched work; or
* universal inline prevention of every invalid token that could be issued by a
  colluding actor and its home Authorization Server.

## Residual Risks

Even when all checks succeed, a valid token chain does not imply that the
requested downstream action is authorized by local business policy. As specified
in Part II, recipients evaluate authorization using only the actor-chain
information actually disclosed to them by the artifact together with token
subject, intended target, and local policy.

Deployments that depend on independently verifiable provenance for high-risk
operations typically require synchronous validation of commitment-linked proof
state or otherwise treat the issuing Authorization Server as the sole trust
anchor.

In the Verified Subset Disclosure and Verified Actor-Only Disclosure profiles,
a current actor signs only the exact actor-visible chain available at that hop.
Those profiles therefore provide non-repudiation over the signed actor-visible chain
and linked commitment state, not over hidden prefix semantics against a rogue or
colluding Authorization Server.

# Trust Boundaries and Audit Guidance {#trust-audit}

The trust model and visible-disclosure properties of the six profiles are
defined in the main specification text and {{threat-model}}. This section focuses on
operational retention and forensic guidance rather than restating those profile
summaries.

Authorization Servers supporting these profiles are expected to retain records
keyed by `acti` and `jti`.

For verified profiles, the retention period is expected to be at least the
maximum validity period of the longest-lived relevant token plus a deployment-
configured audit window, and to remain sufficient to validate historical proofs
across key rotation.

For verified profiles, such records usually include:

* prior token reference;
* authenticated actor identity accepted for the exchange or proof-validation step;
* step proof reference or value;
* issued token reference;
* commitment state;
* requested audience or target context; and
* timestamps.

For subset-disclosure profiles, retained records are expected to also allow
reconstruction of the verified actor-visible chain for each hop and the
disclosed subset issued for each recipient. Collecting all such accepted hop
evidence for one `acti`, including retained tokens, proofs, commitments, and
exchange records, can reconstruct the accepted hop sequence, including
repeated-actor revisits, and can often reveal much of the effective call
graph, but this specification does not by itself yield a complete standardized
graph across related branches. If a deployment also relies on a hidden
full-chain prefix not signed by every acting intermediary, the Authorization
Server is expected to retain the
additional state needed to reconstruct that hidden prefix for later audit.

Actors are also expected to retain local records sufficient to support replay
detection, incident investigation, and later proof of participation.

# Design Rationale and Relationship to Other Work

This document complements [@RFC8693] by defining chain-aware token-exchange
profiles. It also fits alongside the broader SPICE service-to-service and
attestation work [@I-D.ietf-spice-s2s-protocol]
[@I-D.draft-mw-spice-transitive-attestation] and composes with companion
SPICE provenance work: Actor Chain addresses **WHO** acted, Intent Chain
[@I-D.draft-mw-spice-intent-chain] addresses **WHAT** was produced or
transformed, and Inference Chain [@I-D.draft-mw-spice-inference-chain]
addresses **HOW** a result was computed.

This specification defines six profiles instead of one deployment mode
so that implementations can choose among complete disclosed actor chain-based
authorization, trust-first partial disclosure, explicit actor-only operation,
stronger commitment-state accountability, recipient-specific commitment-backed
partial disclosure, and verified actor-only disclosure without changing the
core progression model.

The base specification remains linear. Branching, richer disclosure mechanisms,
and evidence-discovery protocols remain future work because they require
additional identifiers, validation rules, and interoperability work.

## Relationship to TLS-Session-Bound Access Tokens

Actor-chain validation and TLS-session-bound presentation address different
replay points in a multi-hop on-behalf-of flow. TLS-session-bound access tokens
bind presentation of an OAuth access token to a specific mTLS connection using
a proof based on TLS Exporter material and the access-token hash
[@I-D.mw-oauth-tls-session-bound-tokens].

In an A-to-B-to-C flow, TLS-session-bound presentation lets B verify that the
A-to-B token was presented on the current A-to-B mTLS connection. This protects
against replay of that token, or that token together with an old presentation
proof, on a different connection.

Actor-chain validation protects successor-token issuance. When B exchanges the
inbound token for a successor token targeted to C, the Authorization Server
authenticates B as the current actor, validates that B was an intended recipient
of the inbound `subject_token`, and enforces profile-specific chain-continuity,
disclosure, replay, and freshness rules.

Because an Authorization Server normally cannot recompute the TLS Exporter
value for a prior B-terminated connection, deployments that require
Authorization-Server-visible evidence of prior-hop presentation can require B,
or a verifier co-located with B, to submit a signed confirmation that the
inbound token and its session-binding proof were verified before chain
extension.

## Relationship to OAuth Identity and Authorization Chaining Across Domains

OAuth Identity and Authorization Chaining Across Domains defines a pattern for
preserving identity and authorization information when a request crosses OAuth
trust-domain boundaries using a JWT authorization grant and a subsequent access
token request in the target domain [@I-D.ietf-oauth-identity-chaining].

This specification addresses a different, complementary problem: representing,
preserving, validating, and selectively disclosing the actor progression of a
multi-hop workflow across successive token exchanges. In particular, this
specification defines the `actp` profile signal, the stable `acti` workflow
identifier, profile-controlled disclosed `act` processing, append-only actor
progression, and, for verified profiles, actor-signed step proofs and cumulative
`actc` commitment state.

Where both specifications are used in the same deployment, an actor-chain token
or actor-chain state can be carried through a cross-domain exchange according
to local trust policy and the preservation rules in this document. This
document does not require use of OAuth Identity and Authorization Chaining
Across Domains, and that document does not define the actor-chain profile,
disclosure, or commitment semantics defined here.

# Design Decisions

This section records key design decisions made in the core specification so
that future revisions can preserve the underlying interoperability and security
rationale even if the document is later split.

## Why disclosed actor chain state is carried in nested act

The interoperable JWT form uses nested `act` as the single authoritative
inline carrier for disclosed actor-chain state. This avoids maintaining separate
disclosed actor-chain claims and prevents dual-truth bugs in which two different
claims could describe different disclosed histories.

## Why top-level sub remains the workflow subject

Top-level `sub` identifies the workflow subject of the token rather than the
current actor. This keeps profiled access token semantics aligned with RFC 8693 and
allows the current actor to remain visible in `act`. Replacing `sub` with the
current actor or with a constant marker would make token subject semantics much
less clear for recipients and auditors.

## Why privacy-sensitive profiles use stable subject aliases

Subset-disclosure operation can hide actors only if other visible fields do not
reveal the hidden subject indirectly. The Authorization Server therefore chooses a stable
workflow-subject representation at bootstrap, such as a pairwise or
workflow-local alias, and preserves it for the workflow.

## Why subset disclosure is recipient-specific and Authorization-Server-driven

Different recipients in the same workflow can have different need-to-know. The
Authorization Server is therefore the policy decision and enforcement point for disclosure and
may issue a narrower or broader disclosed nested `act` to different recipients,
so long as each returned token remains consistent with the active profile and
any disclosed `act` is a permitted profile-conformant disclosure of the
accepted chain state for that hop.

## Why actor-only is a separate profile even though subset can express it

Actor-only disclosure can be expressed as a special case of subset disclosure,
but this document gives it distinct profile identifiers so that the intended
policy remains explicit and machine-readable to current and future
implementations. A token carrying `actp=declared-actor-only` or
`actp=verified-actor-only` therefore tells every conforming actor and
recipient that profiled access tokens in that workflow expose only the outermost
current actor inline, even though the Authorization Server may retain richer
hidden workflow state for later audit or forensics.

## Why branching is represented across tokens, not inside one token

Each token carries one disclosed path in nested `act`. Branching is represented
by issuing multiple successor tokens that share a prior workflow state. This
keeps token syntax simple while still supporting forensic and legal-audit
reconstruction of a broader call graph from retained Authorization Server records and related
artifacts.

## Why actc uses parent-pointer commitments instead of Merkle trees

The base commitment mechanism is hop-oriented: each accepted successor step
binds exactly one parent commitment state and one new verified hop. Allowing
multiple successors to share the same parent forms a hash-linked workflow graph
without requiring Merkle-tree ordering rules, sibling proof transmission, or
merge semantics. Future work could add Merkle-style aggregation if deployments
need compact set commitments across many branches.

## Why actp and actc use short claim names

These claims appear in every token issued under this specification, and `actc`
also travels in later verified hops. The document therefore uses short claim
names to limit repeated per-hop overhead on the wire. Their meanings are fixed
only by this specification, and the main body defines those semantics before
IANA registration.

## Why RFC 8414 metadata discovery is reused

The specification reuses the standard RFC 8414 authorization-server metadata
endpoint for discovery. This avoids inventing a new discovery API and keeps
capability negotiation in the well-known OAuth metadata channel that
implementations already use.

## Privacy goals and limits

Subset disclosure limits per-hop visibility, but it does not hide information
from the issuing Authorization Server or from colluding parties that pool tokens, proofs,
acknowledgments, and logs. The design therefore treats complete branch and call
graph reconstruction primarily as a forensics or legal-audit concern rather
than an online authorization requirement.

# Compact End-to-End Examples {#compact-examples}

## Example 1: Declared Full Disclosure in One Domain

Assume `A`, `B`, and `C` are governed by `AS1`.

1. `A` requests a token for `B` under the Declared Full Disclosure profile.
2. `AS1` issues `T_A` with `act=EncodeVisibleChain([A])` and `aud=B`.
3. `A` calls `B` and presents `T_A`.
4. `B` validates `T_A`, verifies continuity, and exchanges `T_A` at `AS1` for
   a token to `C`.
5. `AS1` authenticates `B`, verifies that `B` was an intended recipient of the
   inbound token, appends `B`, and issues `T_B` with
   `act=EncodeVisibleChain([A,B])` and `aud=C`.
6. `B` validates that the returned disclosed actor chain is exactly the prior chain plus `B`.
7. `B` presents `T_B` to `C`.
8. `C` validates the token and authorizes based on the disclosed actor chain `[A,B]`.

## Example 2: Declared Subset Disclosure

Assume `A`, `B`, and `C` use the Declared Subset Disclosure profile and
accept the issuing Authorization Server as the trust anchor for disclosure policy.

1. `A` requests a token for `B` under the Declared Subset Disclosure profile.
2. `AS1` issues `T_A` with a recipient-specific `act`
   intended for `B`, or omits `act` entirely according to local policy.
3. `A` calls `B` and presents `T_A`.
4. `B` validates the token and uses only the disclosed actor chain, if any,
   for actor-chain authorization. If `act` is omitted, this specification
   provides no inline actor-chain input beyond what is disclosed; any
   additional authorization inputs come from local policy.
5. `B` exchanges `T_A` at `AS1` for a token to `C`.
6. `AS1` appends `B` to the accepted workflow state for that hop, applies disclosure
   policy for `C`, and issues `T_B` with a recipient-specific `act`, or
   with no `act`, according to local policy.
7. `B` presents `T_B` to `C`.
8. `C` validates the token and authorizes only on the disclosed actor chain, if any. If
   `act` is omitted or does not disclose `B`, this specification provides no inline current-
   actor disclosure for that hop, and `C` treats undisclosed actors as unavailable.

## Example 2b: Declared Actor-Only Disclosure

Assume `A`, `B`, and `C` use the Declared Actor-Only Disclosure profile.

1. `A` requests a token for `B` under the Declared Actor-Only Disclosure profile.
2. `AS1` issues `T_A` with `act=EncodeVisibleChain([A])` and `aud=B`.
3. `A` calls `B` and presents `T_A`.
4. `B` validates that the disclosed `act` identifies only the current actor
   `A` and authorizes only on that actor and local policy.
5. `B` exchanges `T_A` at `AS1` for a token to `C`.
6. `AS1` issues `T_B` with `act=EncodeVisibleChain([B])` and `aud=C`.
7. `B` presents `T_B` to `C`.
8. `C` validates the token and authorizes only on the disclosed current actor
   `B` and local policy.

## Example 3: Verified Full Disclosure Across Two Domains

Assume `A` and `B` are governed by `AS1`, while `C` is governed by `AS2`.

1. `A` obtains bootstrap context from `AS1`, signs `chain_sig_A`, and receives
   `T_A` with `act=EncodeVisibleChain([A])` and `actc`.
2. `A` calls `B` with `T_A`.
3. `B` validates `T_A`, constructs `[A,B]`, signs `chain_sig_B`, and exchanges
   `T_A` at `AS1` for a token to `C`.
4. `AS1` verifies `chain_sig_B` submitted as `actor_chain_step_proof`,
   updates the commitment, and issues `T_B` with
   `act=EncodeVisibleChain([A,B])` and `aud=C`.
5. Because `C` does not trust `AS1` directly, `B` performs a second exchange at
   `AS2`.
6. `AS2` preserves `actp`, `acti`, `act=EncodeVisibleChain([A,B])`, and
   `actc`, and issues a local token trusted by `C` that still
   represents `B`.
7. `C` validates the local token, sees the disclosed actor chain `[A,B]`, and
   authorizes accordingly.

## Example 4: Verified Actor-Only Disclosure

Assume `A`, `B`, and `C` use the Verified Actor-Only Disclosure profile.

1. `A` obtains bootstrap context, signs `chain_sig_A` over disclosed actor chain `[A]`,
   and receives `T_A` with `act=EncodeVisibleChain([A])` and `actc`.
2. `A` calls `B` with `T_A`.
3. `B` validates `T_A`, verifies that `A` is the presenter, constructs the
   verified actor-visible chain `[A,B]`, signs `chain_sig_B`, and exchanges
   `T_A` at its home Authorization Server to obtain `T_B` for `C`.
4. `T_B` contains the updated `actc` and disclosed `act=EncodeVisibleChain([B])`.
5. `B` presents `T_B` to `C`.
6. `C` validates the token and authorizes based only on the disclosed current actor
   `B` and local policy. `C` does not infer prior-actor identity or count
   from undisclosed information or from `actc` alone.

## Example 5: Verified Subset Disclosure

Assume `A`, `B`, and `C` use the Verified Subset Disclosure profile.

1. `A` obtains bootstrap context, signs `chain_sig_A`, and receives `T_A` with
   a recipient-specific `act`, or with no `act`, plus `actc` intended
   for `B` according to local policy.
2. `A` calls `B` and presents `T_A`.
3. `B` validates the token and uses only the disclosed actor chain, if any, for actor-chain
   authorization. If `act` is omitted, this specification provides no inline actor-chain
   input beyond what is disclosed; any additional authorization inputs come from local policy.
4. `B` signs `chain_sig_B` over the exact actor-visible chain that `B`
   verified on the inbound hop, with `B` appended, and exchanges `T_A` at its
   home Authorization Server alongside `chain_sig_B` as `actor_chain_step_proof` to obtain `T_B`
   for `C`.
5. `AS1` verifies that submitted chain state, applies disclosure policy for `C`,
   and issues `T_B` with a recipient-specific `act`, or with no `act`,
   and updated `actc`.
6. `B` presents `T_B` to `C`.
7. `C` validates the token and authorizes only on the disclosed actor chain, if any. If
   `act` is omitted or does not disclose `B`, this specification provides no inline current-
   actor disclosure for that hop, and `C` treats undisclosed actors as unavailable.
8. If later audit is needed, the verified actor-visible chain for the hop can
   be reconstructed from retained step proofs together with exchange records
   and, when subset disclosure omitted `act`, any retained Authorization-Server
   workflow records needed to supply hidden continuity context.

# Illustrative Wire-Format Example

This section shows one abbreviated decoded JWT payload together with one
abbreviated decoded `actc` JWS payload. The values are
illustrative and signatures are omitted for readability.

## Decoded Access Token Payload Example

~~~ json
{
  "iss": "https://as.example",
  "sub": "svc:planner",
  "act": {
    "iss": "https://as.example",
    "sub": "svc:planner",
    "act": {
      "iss": "https://as.example",
      "sub": "svc:orchestrator"
    }
  },
  "aud": "https://api.example",
  "exp": 1760000000,
  "jti": "2b2b6f0d3f0f4d7a8c4c3c4f9e9b1a10",
  "acti": "6cb5f0c14ab84718a69d96d31d95f3c4",
  "actp": "verified-full",
  "actc": "<compact JWS string>"
}
~~~

## Decoded actc JWS Example

Protected header:

~~~ json
{"alg":"ES256","typ":"act-commitment+jwt"}
~~~

Payload:

~~~ json
{
  "ctx": "actor-chain-commitment-v1",
  "iss": "https://as.example",
  "acti": "6cb5f0c14ab84718a69d96d31d95f3c4",
  "actp": "verified-full",
  "halg": "sha-256",
  "prev": "SGlnaGx5SWxsdXN0cmF0aXZlUHJldkRpZ2VzdA",
  "step_hash": "z7mq8c0u9b2C0X5Q2m4Y1q3r7n6s5t4u3v2w1x0y9z8",
  "curr": "Vb8mR6b2vS5h6S8Y6j5X4r3w2q1p0n9m8l7k6j5h4g3"
}
~~~

On the wire, the `actc` claim carries the usual compact-JWS
form:

~~~ text
BASE64URL(protected-header) "." BASE64URL(payload) "." BASE64URL(signature)
~~~

# Canonicalization Test Vectors {#canonicalization-test-vectors}

The following illustrative vectors are intended to reduce interoperability
failures caused by divergent canonicalization. They are not exhaustive, but
they provide concrete byte-for-byte examples for common JWT/JCS ActorID and
`target_context` inputs.

## JWT / JCS ActorID Example

Input object:

~~~ json
{"iss":"https://as.example","sub":"svc:planner"}
~~~

JCS serialization (UTF-8 bytes rendered as hex):

~~~ text
7b22697373223a2268747470733a2f2f61732e6578616d706c65222c22737562223a227376633a706c616e6e6572227d
~~~

SHA-256 over those bytes:

~~~ text
7a14a23707a3a723fd6437a4a0037cc974150e2d1b63f4d64c6022196a57b69f
~~~

## JWT / JCS target_context Example

Input object:

~~~ json
{"aud":"https://api.example","method":"invoke","resource":"calendar.read"}
~~~

JCS serialization (UTF-8 bytes rendered as hex):

~~~ text
7b22617564223a2268747470733a2f2f6170692e6578616d706c65222c226d6574686f64223a22696e766f6b65222c227265736f75726365223a2263616c656e6461722e72656164227d
~~~

SHA-256 over those bytes:

~~~ text
911427869c76f397e096279057dd1396fe2eda1ac9e313b357d9cecc44aa811e
~~~

# Implementation Conformance Checklist (Informative)

This checklist is an implementation aid. Conformance is defined in
{{conformance}} and in the normative sections referenced there.

Implementers can use the following checklist to verify that they have
addressed the main requirements for each supported profile:

| Requirement | Draft section reference | Implemented [ ] |
| --- | --- | --- |
| Stable generation, uniqueness, retention-period non-reuse, and preservation of `acti`, using a CSPRNG with at least 122 bits of entropy | {{actor-chain-identifier}} | [ ] |
| Local policy for actor authentication or presenter binding, if relied upon | {{actor-authentication}} | [ ] |
| Exact ActorID equality over (`iss`, `sub`) | {{actor-identity}} | [ ] |
| Canonical serialization for all proof and commitment inputs | {{canonicalization}}; {{target-context}}; {{canonicalization-test-vectors}} | [ ] |
| Single logical chain-extending recipient and target-context comparison | {{target-context}}; {{verified-common-processing}} | [ ] |
| Intended-recipient validation during token exchange | {{intended-recipient}} | [ ] |
| Replay and freshness handling for tokens and step proofs | {{replay-freshness}} | [ ] |
| Configurable chain-depth enforcement | {{chain-depth-limits}} | [ ] |
| Exact append-only checks for full-disclosure profiles | {{declared-full}}; {{verified-full}} | [ ] |
| Correct ordered-subsequence validation for subset-disclosure profiles | {{declared-subset}}; {{verified-subset}} | [ ] |
| Current-actor-only validation for actor-only profiles | {{declared-actor-only}}; {{verified-actor-only}} | [ ] |
| Exact commitment verification for verified profiles | {{commitment-function}}; {{verified-full}}; {{verified-subset}}; {{verified-actor-only}} | [ ] |
| Proof-key binding between ActorID and proof signer under local trust policy | {{proof-keys}} | [ ] |
| Non-broadening Refresh-Exchange processing, if supported | {{refresh-exchange}} | [ ] |
| Correct binding and one-time redemption of bootstrap context for verified workflows | {{verified-bootstrap-context}}; {{verified-initial-step}} | [ ] |
| Policy for when `hop_ack` is optional or required | {{hop-ack}} | [ ] |
| Preserve-state handling for cross-domain re-issuance and Refresh-Exchange, including represented-current-actor authorization | {{preserve-state-exchanges}}; {{cross-domain-reissuance}}; {{refresh-exchange}} | [ ] |
| Cross-domain preserve-or-reject handling for unmapped `target_context` members | {{target-context}}; {{cross-domain-reissuance}} | [ ] |
| Privacy-preserving handling of logs and error messages | {{error-handling}}; {{privacy}} | [ ] |

# Future Considerations

## Terminal Receipts and Result Attestations

This specification defines special handling for the first actor in order to
initialize chain state. It does not define corresponding terminal-hop semantics
for a final recipient that performs work locally and does not extend the chain
further.

Deployments that need richer terminal execution or result evidence can compose
this specification with companion SPICE provenance work, such as Intent Chain
[@I-D.draft-mw-spice-intent-chain] and Inference Chain
[@I-D.draft-mw-spice-inference-chain], to provide complementary WHAT and HOW
evidence. However, this specification itself does not define the terminal
receipt/execution/result artifact or the precise composition rules by which
such companion artifacts satisfy terminal-hop evidence requirements.

Future work could define:

* a terminal receipt proving that the recipient accepted the request;
* an execution attestation proving that the recipient executed a specific
  operation; and
* a result attestation binding an outcome or result digest to the final
  commitment state.

## Bootstrap Receipts and Portable Initial-State Evidence

This specification does not define a bootstrap-signed receipt artifact. Later
audit of bootstrap processing therefore relies on Authorization Server records,
the bootstrap response, the initial step proof, and the first issued profiled access token.

Future work could define a portable bootstrap receipt or bootstrap
attestation artifact if deployments need independently portable evidence of
workflow initialization outside Authorization Server logs.

## Receiver Acceptance and Unsolicited Victim Mitigation

This specification deliberately does not append a recipient merely because that
recipient was contacted. It also defines an optional `hop_ack` extension that
lets a recipient prove accepted responsibility for a hop.

However, this specification still does not by itself prevent a malicious actor
from sending a validly issued token to an unsolicited victim service. Future
work can define stronger receiver-driven protections, including:

* stronger result attestations for completed terminal work;
* a challenge-response model for high-risk terminal hops; and
* recipient-issued nonces or capabilities that would need to be bound into
  the final accepted hop.

## Recipient-Protected Disclosure Mechanisms

The normative subset-disclosure rules in Privacy Requirements and
Considerations define the base disclosed `act` representation. Future work could
specify recipient-protected or selectively revealable presentation mechanisms,
such as SD-JWT [@RFC9901], COSE/CBOR bindings, encrypted envelopes, or
zero-knowledge techniques, without changing the base disclosure semantics.

## Semantic-Equivalent Commitment Inputs

This version binds commitment linkage to exact compact-JWS proof bytes.
Future work could define an optional semantic-equivalence commitment input,
for example by hashing a canonical semantic proof object while still retaining
artifact-byte evidence for provenance and non-repudiation.

## Branching and Fan-Out

This specification defines one disclosed path per issued token and does not
standardize merge or sibling-discovery semantics across multiple descendants
that share earlier workflow history.

An Authorization Server could nevertheless mint multiple accepted successor
tokens from one prior accepted state. Such branching is represented across
multiple tokens, not inside one token's nested `act` structure. Later
reconstruction of the resulting call graph is primarily a forensic or legal-
audit concern.

Future work could define explicit branch identifiers, parent-child workflow
correlation, tree-structured commitment verification, inclusion proofs, partial
disclosure across branches, and later merge behavior. Such future work could
also help correlate related **WHO**, **WHAT**, and **HOW** evidence across
companion Actor Chain, Intent Chain [@I-D.draft-mw-spice-intent-chain], and
Inference Chain [@I-D.draft-mw-spice-inference-chain] deployments.

## Evidence Discovery and Governance Interoperability

Proof-bound profiles derive much of their value from later verification of
step proofs and exchange records. Future work could standardize interoperable
evidence discovery, retention, and verification-material publication.

Any such specification should define, at minimum, evidence object typing,
authorization and privacy controls for cross-domain retrieval, stable lookup
keys such as `jti` or `acti`, error handling, and retention expectations.

# Out-of-Scope Use Cases {#use-cases}

This section is informative. Per-hop request binding - cryptographic
evidence that a request physically traversed each claimed hop - is out of
scope for this document. End-to-end path proof in the data plane, such as
nested message signatures applied by each actor in turn, requires a companion
mechanism such as [@RFC9421] or [@RFC9449] and is not addressed here.

# Relationship to RFC 8693: Detailed Comparison {#relationship-to-rfc8693}

This section is informative. [@RFC8693] defines token exchange and
introduces `act` for delegation, with nested `act` described as a convention.
It treats `act` as optional and defines no normative processing rules for
construction, extension, or validation across a sequence of exchanges. This
document does not replace [@RFC8693]; with `actp` absent, it adds no new
requirements. With `actp` present, the following constraints apply:

| [@RFC8693] behavior | This document |
| --- | --- |
| `act` is optional. | Processing follows the rules here when used; `actp` makes the governing semantics explicit. |
| Nested `act` is a convention. | Nested `act` is normative structural form; recipients can rely on its shape. |
| No append-only rule. | Prior actors are not inserted, reordered, deleted, or modified. |
| No cross-exchange correlation. | `acti` provides a stable workflow instance identifier across hops. |
| No integrity binding beyond the issuing Authorization Server's signature. | `actc` provides cumulative commitment state that can survive Authorization Server boundary crossings. |
| No prior-actor disclosure control. | `actp` profiles scope disclosure; the actor-chain disclosure boundary prevents leakage through other claims. |
| No disclosure-regime signal to the recipient. | `actp` allows recipients to apply the correct interpretation. |

{backmatter}

<reference anchor="IANA.Hash.Algorithms" target="https://www.iana.org/assignments/named-information">
  <front>
    <title>Named Information Hash Algorithm Registry</title>
    <author>
      <organization>IANA</organization>
    </author>
  </front>
</reference>
