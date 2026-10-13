%%%
title = "OAuth Actor Chain: Protocol and Interoperability"
abbrev = "ACTOR-CHAIN-PROTOCOL"
category = "std"
docname = "draft-mw-oauth-actor-chain-02"
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
  "AI agents"
]
date = 2026-10-10

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-oauth-actor-chain-02"
stream = "IETF"
status = "standard"

[[author]]
initials = "A."
surname = "Prasad"
fullname = "A Prasad"
  [author.address]
  email = "ap1729@gmail.com"

[[author]]
initials = "R."
surname = "Krishnan"
fullname = "Ram Krishnan"
  [author.address]
  email = "ramkri123@gmail.com"

[[author]]
initials = "D."
surname = "Lopez"
fullname = "Diego R. Lopez"
  [author.address]
  email = "diego.r.lopez@telefonica.com"

[[author]]
initials = "S."
surname = "Addepalli"
fullname = "Srinivasa Addepalli"
  [author.address]
  email = "srinivasa.addepalli@aryaka.com"

[[author]]
initials = "S."
surname = "Krishnan"
fullname = "Suresh Krishnan"
  [author.address]
  email = "suresh.krishnan@gmail.com"

[normative]
RFC2119 = {}
RFC3986 = {}
RFC6749 = {}
RFC6750 = {}
RFC6755 = {}
RFC6838 = {}
RFC7515 = {}
RFC7518 = {}
RFC7519 = {}
RFC7523 = {}
RFC7638 = {}
RFC7662 = {}
RFC8174 = {}
RFC8414 = {}
RFC8693 = {}
RFC8707 = {}
RFC8725 = {}
RFC8785 = {}
RFC9110 = {}
RFC9449 = {}
RFC9728 = {}
RFC9864 = {}

[normative."I-D.ietf-oauth-identity-chaining"]
  title = "OAuth Identity and Authorization Chaining Across Domains"
  [normative."I-D.ietf-oauth-identity-chaining".target]
    href = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining"

[informative]
RFC9901 = {}

%%%

.# Abstract

This document defines the protocol and interoperability requirements for
OAuth Actor Chain. Six profiles combine Authorization Server declarations or
actor-signed evidence with Full, Subset, or Actor-Only disclosure. Verified
profiles create one actor proof and one AS acceptance at every actor step,
with optional current-actor, disclosed-actor, or full-path evidence delivered
inline or through introspection. This specification defines the wire formats, validation,
replay and retry behavior, cross-domain preservation, resource limits, and
IANA registration requests. A separate Informational overview provides
additional design discussion. This revision continues the existing OAuth Actor
Chain draft series, with Internet-Draft lineage beginning in SPICE in
February 2026.

{mainmatter}

# Introduction {#introduction}

Applications often delegate a request across several services before reaching
a protected resource. The resource may need evidence about earlier actors,
while disclosure policy limits which identities and relationships it may learn.
For example, a document API may require evidence from the initiating service
and its immediate connector without needing every intermediary's identity.

OAuth 2.0 Token Exchange [@!RFC8693] supports exchanging credentials and
representing actor history in nested `act` claims. Earlier actors in that
history remain informational for access control. Actor Chain adds explicit
rules for constructing the history, controlling disclosure, and delivering
actor-signed evidence through a separate top-level extension. It retains the
Authorization Server's (AS's) responsibility for authorization and token issuance.

## Participants and Workflow

Consider services A, B, and C acting for one workflow subject, with C calling
protected resource D:

~~~ text
A -> B -> C -> D
~~~

A obtains a token for B. After accepting A's call, B authenticates to an AS
and exchanges the received token for a token addressed to C. C similarly
obtains a token addressed to D. Each exchange requires authorization to act
on the inbound token; possession of that token alone does not grant exchange
permission or transfer its sender's private key.

In this example, each service requesting a new authorization transition is an
actor. The AS
authenticates that actor, checks the inbound authority and outgoing target,
applies disclosure policy, and issues the next access token. The resource
validates its token and applies its own authorization and evidence policy.
The token subject identifies the party or context represented by the workflow;
it is distinct from the actor performing an individual transition.

For Verified assurance, C signs a request binding its identity, workflow,
preceding acceptance, accepting AS, resource, and any requested scope. The AS
validates that request and signs an acceptance of its exact proof. C's proof,
the AS acceptance, and the issued access token have different roles: the proof
authenticates C's request, the acceptance records the AS's decision to accept
that step, and the access token conveys the authority granted for access to D.

## Processing Model

There are three transitions:

| Transition | Meaning |
| --- | --- |
| `root` | Begins a workflow with its first authenticated actor. |
| `extend` | Appends an authenticated actor to accepted workflow state. |
| `preserve` | Transfers accepted state across AS domains without adding an actor step. |

Each Verified `root` or `extend` creates one actor proof and one AS acceptance.
A Verified token carries the latest acceptance in `actc`. Its exact bytes link
a later actor's proof to that predecessor. A `preserve` transition retains the
protected state and original signatures; an AS boundary is not itself actor
participation. Reusing an access token for another call does not create a new
Actor Chain transition.

## Assurance, Disclosure, and Evidence

A workflow selects one assurance/disclosure profile and keeps it fixed.
Declared assurance relies on the AS's signed assertion. Verified assurance
adds actor proofs and AS acceptances. Independently, Full disclosure shows the
accepted actor path, Subset shows an authorized subsequence, and Actor-Only
shows the current actor. For A, B, and C, those disclosures could be A/B/C,
A/C, and C. A/C does not establish adjacency or the absence of B.

Evidence delivery is a further choice within Verified profiles. A token with
`actc` and no `acte` carries the AS acceptance without supplying actor proofs.
When `acte` is present, `current` supplies the latest proof and acceptance;
`disclosed` supplies one original pair per disclosed actor occurrence; and
`path` supplies a continuous root-to-current sequence with actor-view openings.
`path` requires Full disclosure. `disclosed` verifies selected signatures but
relies on issuer-attested membership and order across omitted actors.

Resources advertise evidence requirements through authenticated metadata.
Evidence can travel inline or through authorized token introspection. Required
evidence must be available and compatible with disclosure policy. Its absence
cannot be treated as successful direct verification.

Actor signatures authenticate protocol requests, not business approval or
successful execution. One verified path does not establish that no other branch
exists. An exchange-time signature also does not prove who presents the token
now; reliance on the immediate actor as live presenter requires a separately
validated sender constraint.

## Reading Guide and Lineage

This specification defines the protocol model and conformance requirements
for Actor Chain. The Informational overview
[@ACTOR-CHAIN-OVERVIEW] offers additional motivation and design discussion;
reading it first is optional. The sections below define the standards boundary,
profiles, wire artifacts, transition processing, validation, and failure rules,
followed by security considerations and worked examples. Examples and test
vectors are informative aids; the normative processing requirements govern.

This is revision `-02` of the existing `draft-mw-oauth-actor-chain` series,
following `-01` dated 15 June 2026 [@OAUTH-ACTOR-CHAIN-01]. The authors'
Actor Chain Internet-Draft lineage began with SPICE `-00` dated 25 February
2026 [@SPICE-ACTOR-CHAIN-00]; Datatracker records the SPICE series as replaced
by the OAuth series. The separate overview complements this continuing
technical specification.

# Standards Boundary {#standards-boundary}

This document profiles OAuth 2.0 Token Exchange and does not change the base
meaning of `sub`, `act`, or `may_act`. When `actp` is absent, this document adds
no processing rules. Earlier actors in nested `act` remain informational for
access-control purposes as specified by RFC 8693.

When `actp` selects a profile in this document:

* the token-level `sub` remains the subject of the workflow;
* `act` names the actors disclosed in that token; it does not change `sub`;
* `may_act` retains its RFC 8693 meaning as a statement about who may act; it
  does not record an Actor Chain transition;
* `acti` identifies this sequence of actor transitions as one workflow; and
* in a Verified profile, `actc` carries the AS acceptance and optional `acte`
  delivers actor-signed evidence to the recipient.

This specification does not define application roles, business policy,
transaction semantics, task execution, result correctness, complete branch
discovery, or a general delegation-policy language. It compares OAuth `scope`
as written; differently named scopes in different domains are not assumed to
mean the same thing.

# Authorization Policy Model {#authorization-policy-model}

The AS applies issuance policy to its authoritative accepted workflow state.
The recipient applies normal OAuth authorization and its configured evidence
policy. RFC 8693 Section 4.1's rule for earlier nested `act` identities is
preserved: those identities alone remain informational. This profile defines
the top-level `acte` extension as an additional source of authenticated actor
records. Section (#evidence-authorization, use counter) specifies its use.

With `disclosed` coverage, the recipient verifies the actors disclosed to it.
It trusts the token issuer's attestation that the selected records belong to
this token's accepted path. It need not obtain or verify undisclosed actors;
different authorized recipients can receive and verify different subsets.
For example, a recipient requiring A and C can verify their disclosed records
without B's proof. A recipient requiring B must receive and verify B's evidence;
another recipient's check satisfies that requirement only under an explicit
local trust policy. Complete-path verification is an additional policy choice,
not a requirement of `disclosed` coverage.
Participation does not establish business approval, argument-level permission,
or execution results. Application policy determines which authenticated
records are relevant; this specification defines no role or approval language.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals.

This document uses OAuth terminology from [@!RFC6749] and [@RFC8693]. It also
defines:

* **ActorID**: the issuer-qualified actor identifier `{ "iss": ..., "sub":
  ... }`.
* **Current actor**: the actor authenticated by the AS for a `root` or `extend`
  transition.
* **Presenting actor**: the entity that presents the issued access token to
  its recipient.
* **Actor-visible chain**: the ordered ActorID sequence the current actor is
  authorized to know at its transition. The actor commits to that sequence
  without exposing it in the step proof.
* **Disclosed chain**: the ordered ActorID sequence shown in a token's nested
  `act` claim. Disclosure can be narrower than the actor-visible chain.
* **Acceptance**: the AS-signed compact JWS, carried as `actc`, that accepts
  one exact actor proof and links it to the preceding acceptance, if any.
* **Evidence coverage**: `current` supplies the latest proof and acceptance;
  `disclosed` supplies the original proof and acceptance for each disclosed
  actor occurrence; `path` supplies the continuous root-to-current proofs,
  acceptances, and actor-view openings.
* **Evidence delivery**: `inline` carries evidence in the token;
  `introspection` supplies it through authenticated token introspection.
* **Commitment-only**: a Verified token carrying `actc` without `acte`.
* **Protected state**: `actp`, `acti`, `actc`, and any carried `acte`. A
  `preserve` transition transports these values without transcription.

# Profiles: Assurance and Disclosure {#profiles}

Each profile makes two separate choices: how an actor transition is supported
(*assurance*) and how much actor history a token reveals (*disclosure*).
Declared assurance relies on the issuing AS's assertion. Verified assurance
adds an actor proof and AS acceptance at each actor transition. Full disclosure
shows the whole actor path; Subset shows an authorized subset; Actor-Only shows
only the current actor. These choices yield six profiles:

| Assurance | Full | Subset | Actor-Only |
| --- | --- | --- | --- |
| Declared | `declared-full` | `declared-subset` | `declared-actor-only` |
| Verified | `verified-full` | `verified-subset` | `verified-actor-only` |

The evidence option is separate from the six profiles. In a Verified profile,
`current` permits direct verification of the latest actor proof. `disclosed`
permits direct verification of every actor occurrence in the token's `act`,
with issuer-attested membership in this token's accepted path. `path` permits
direct verification of every actor proof and original AS acceptance on one
root-to-current path, and is available only with Full disclosure in this
version.

These artifacts prove only the checks specified here. Neither `actc` nor `acte`
proves that an actor performed a task, produced a correct result, remained
uncompromised, or that every branch or off-protocol actor was disclosed. Live
possession by the token presenter requires a separate sender constraint.

# Conformance {#conformance}

An implementation MAY support any subset of the six profiles, but MUST publish
its supported capabilities as specified in Section
(#as-metadata, use counter). For each profile it accepts, the implementation
MUST apply the common rules and the rules for that profile's assurance and
disclosure choices.

The request selects exactly one `actor_chain_profile`. The AS either issues a
token with the matching `actp` value or rejects the request. `actp` and the
workflow identifier `acti` remain unchanged throughout that workflow. A party
MUST NOT infer a profile from the shape of `act` or from `acte`.

Unknown profile values, versions, transition kinds, evidence coverage values,
delivery values, or protected artifact types, and missing required members,
MUST fail closed. That means processing stops rather than guessing a default. JSON
objects used by this specification MUST reject duplicate members.

# Common Data Model {#data-model}

Self-contained profiled access tokens MUST be signed JWTs [@!RFC7519] and MUST contain
`iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `actp`, and `acti`. They carry `act`
as required by the selected disclosure mode. Verified tokens MUST additionally
carry `actc` and MAY carry `acte`.

An ActorID is a JSON object containing exactly two non-empty string members:
`iss` and `sub`. In this object, `sub` identifies the actor; it is distinct
from the access token's top-level workflow subject. `iss` is an absolute issuer
URI. ActorID equality is exact equality of the pair. Newly issued nested `act`
nodes MUST carry both members.

`VisibleChain(act)` reads nested `act` from the innermost prior actor to the
outermost current actor. `EncodeVisibleChain([A,B])` is:

~~~ json
{
  "iss": "B.iss",
  "sub": "B.sub",
  "act": { "iss": "A.iss", "sub": "A.sub" }
}
~~~

The AS MUST mint `acti` at `root` using a CSPRNG with at least 122 bits of
entropy. It MUST remain stable and MUST NOT encode actor, profile, target, or
business information.

Profiled access tokens SHOULD normally expire within one to ten minutes after
issuance. Implementations MUST validate `iss`, `aud`, `exp`, and `jti` according
to their governing OAuth and JWT specifications before Actor Chain processing.

# Target And Scope Binding {#target-scope}

A Verified actor transition targets one protected resource, such as the
destination API. The proof's `target_context` has a required `resource` member
and may have a `scope` member:

~~~ json
{ "resource": "https://api.example/", "scope": "read" }
~~~

`resource` is one non-empty string. It MUST equal the single RFC 8707
[@!RFC8707] `resource` value in the request and MUST be an HTTPS Resource
Identifier without a fragment as defined by RFC 9728 [@!RFC9728]. It MUST NOT
contain user information. A query component SHOULD be omitted unless the
deployment requires it. Actor Chain
transitions MUST NOT request more than one resource. Fan-out uses distinct
tokens and distinct `request_id` values.

Identifiers covered by a proof must match exactly. This specification compares
Unicode code points after JSON unescaping, with no Unicode normalization.
Implementations MUST NOT case-fold a scheme or host, remove a default port,
add or remove a trailing slash, resolve dot segments, decode percent-encoding,
reorder a query, follow a redirect, or apply another URI normalization before comparing a signed
identifier. Parsing to enforce URI syntax is allowed; changing the string
before comparison is not. Producers SHOULD publish and sign one stable form.
A signed target is an identifier. It MUST NOT be dereferenced merely because
it appears in a valid proof. Exact string comparison avoids security-dependent
differences among URI libraries [@!RFC3986].

`accepting_issuer` MUST be an RFC 8414 issuer identifier and MUST equal, under
the same exact comparison rule, both the authenticated AS metadata `issuer`
and the acceptance `iss`.

The actor proof does not duplicate the access token's `aud`. RFC 8707 permits
an AS to use the `resource` value as the audience or map it to another audience
identifier. The AS MUST audience-restrict the token to the proof-bound resource
using its established mapping and MUST NOT retarget the proof. A recipient
validates token `aud` independently under JWT and its OAuth profile; a JWT
audience may be one string or an array, and every comparison is the exact,
case-sensitive comparison defined by RFC 7519 [@!RFC7519]. This separation
keeps an AS-local audience mapping from becoming portable actor-signed state.

For a Verified `root` or `extend`, requested OAuth `scope` and
`target_context.scope` MUST either both be present or both be absent. When
present, each MUST satisfy the scope grammar in RFC 6749 Section 3.3
[@!RFC6749] and describe the same lexical set. The proof uses the canonical
form: reject duplicates, sort tokens by ascending ASCII value, and join them
with one U+0020 SPACE. Scope tokens are case-sensitive. Empty strings,
leading or trailing spaces, repeated separators, and non-scope-token
characters MUST be rejected.

When both members are absent, the actor authorizes the empty OAuth scope
set. For these Verified transitions, the AS's predefined default under
RFC 6749 Section 3.3 MUST be that empty set. An AS that cannot apply this
default MUST reject an omitted-scope request with `invalid_scope`. The AS
MUST NOT apply a non-empty default scope or issue a token with
non-empty scope. An empty granted set omits token `scope`; a non-empty
granted set MUST be stated explicitly in the token. Required default scopes
must be known before signing and explicitly included in the proof and token
request. An AS that cannot issue under these rules MUST reject with
`invalid_scope`. These constraints apply only to Verified transitions;
Declared processing retains the governing OAuth scope rules.

The AS either issues for the exact proof-bound resource or rejects; it does not
"narrow" one URI into another. It MAY narrow scope. Scope narrowing is set
inclusion over lexical scope tokens. This rule does not establish semantic
equivalence between differently named cross-domain scopes. Cross-domain scope
translation requires an explicitly authorized mapping, as specified in
Section (#cross-domain, use counter). An unknown mapping MUST be rejected.

Each proof binds the outgoing target for that transition only. In `A -> B -> C
-> D`, the successive resources can legitimately identify B, C, and D; those
URIs do not form an ordered set. Each accepting AS validates its transition's
request, proof, issued token, and authorization. D can directly compare the
final proof with D's authenticated RFC 9728 `resource` identifier. Without a
retained historical token, path evidence does not reconstruct the audience or
effective authority of that historical token.

# Actor-View Commitment {#view-commitment}

The actor proof does not carry a clear growing actor path. It carries a salted
commitment to the exact actor-visible ActorID array. Let `salt32` be 32 random
octets freshly generated for the transition. The commitment is:

~~~ text
b64url(SHA-256(
  ASCII("urn:ietf:params:oauth:actor-chain:view:v1") || 0x00 ||
  salt32 || 0x00 || JCS(actor_view_array)))
~~~

JCS is the JSON Canonicalization Scheme [@!RFC8785]. `b64url` is unpadded
base64url as defined by [@!RFC7515]. SHA-256 is fixed for this commitment
version; there is no per-workflow hash negotiation.

The actor supplies an opening containing `salt` and `act` to the accepting AS
in the `actor_chain_view_opening` request parameter. That parameter is the
base64url encoding of the UTF-8 JCS representation of:

~~~ json
{
  "salt": "<base64url 32 octets>",
  "act": [
    { "iss": "https://actors.example/a", "sub": "A" }
  ]
}
~~~

The opening contains exactly `salt` and `act`. `salt` MUST decode to exactly
32 octets. `act` MUST be a non-empty array of valid ActorIDs in actor-visible
order. The decoded parameter MUST equal its UTF-8 JCS representation.

The AS MUST validate the opening against authenticated actor identity, inbound
state, append-only processing, disclosure policy, and the proof commitment. It
MUST NOT place the opening in `current` evidence.

# Actor Step Proof {#step-proof}

Every Verified `root` and `extend` transition creates exactly one actor step
proof. It is a compact JWS whose protected header contains exactly `alg`,
`kid`, and `typ`, with `typ=oauth-act-step+jwt`. The following example uses
`ES256`; permitted algorithms are defined in Section (#bindings, use counter):

~~~ json
{ "alg": "ES256", "kid": "<key identifier>",
  "typ": "oauth-act-step+jwt" }
~~~

The payload has version `v=2`. A `root` payload contains exactly:

~~~ json
{
  "v": 2,
  "kind": "root",
  "actp": "verified-full",
  "acti": "<workflow identifier>",
  "actor": { "iss": "https://actors.example/a", "sub": "A" },
  "sub": "<workflow subject>",
  "accepting_issuer": "https://as1.example",
  "target_context": {
    "resource": "https://api.example/",
    "scope": "read"
  },
  "view_commitment": "<base64url SHA-256>",
  "request_id": "<request-unique identifier>",
  "iat": 1786827601
}
~~~

An `extend` payload contains the same members with `kind=extend` and one
additional member:

~~~ json
"prev": "<b64url SHA-256 of exact preceding compact actc>"
~~~

The actor key MUST be independently authorized for the exact ActorID in
`actor`. A valid signature from a key associated with another actor MUST be
rejected. The `actor` MUST equal the authenticated current actor; `actp`,
`acti`, and `sub` MUST equal accepted workflow state; `accepting_issuer` MUST
identify the AS processing the transition; and `iat` MUST be an integer
NumericDate within the AS acceptance window measured against the AS clock. A
default maximum age of 60 seconds, plus a separately configured allowance for
future clock skew, is RECOMMENDED.

`request_id` MUST be a non-empty string of at most 128 UTF-8 octets. The actor
MUST assign a fresh value to every intended `root` or `extend` transition and
MUST NOT intentionally reuse it for a different proof. The probability of an
accidental duplicate in the same accepting-issuer, ActorID, and workflow
context MUST be negligible. At least 96 bits of pseudorandom data or a UUIDv4
value is sufficient, following the equivalent identifier guidance in
[@!RFC9449].

The proof binds authorization requested by the actor. It does not require the
AS to issue that authority. The AS MAY narrow the result but MUST NOT broaden
it.

# Authorization Server Acceptance {#acceptance}

After accepting a Verified actor proof, the AS creates one compact JWS `actc`.
Its protected header contains exactly `alg`, `kid`, and
`typ=oauth-actc+jwt`. Its payload has version `v=2`.

A root acceptance contains exactly:

~~~ json
{
  "v": 2,
  "kind": "root",
  "iss": "https://as1.example",
  "acti": "<workflow identifier>",
  "actp": "verified-full",
  "step_hash": "<b64url SHA-256 of exact proof compact JWS>",
  "accepted_at": 1786827651
}
~~~

An extend acceptance additionally contains:

~~~ json
"prev": "<b64url SHA-256 of exact preceding compact actc>"
~~~

The AS signature key MUST be authorized for `iss` at `accepted_at`.
`step_hash` is computed over the ASCII octets of the exact proof compact JWS.
For `extend`, `prev` is computed over the ASCII octets of the exact prior
compact `actc`. `kind`, `acti`, `actp`, and `prev` MUST equal the proof values,
and `iss` MUST equal the proof's `accepting_issuer`.

`accepted_at` MUST be the AS time at acceptance. It MUST NOT precede proof
`iat` by more than permitted future clock skew or exceed proof `iat` by more
than the configured acceptance window. A later evidence verifier checks this
signed relationship; it does not apply the original short proof-freshness
window relative to its current clock.

The exact compact `actc` is the current chain head. There is no separately
transported `curr`, negotiated `halg`, or repeated evidence head. Re-encoding
an `actc` changes the artifact and therefore changes successor linkage.

# Evidence Envelope {#evidence}

`acte` is OPTIONAL in a Verified access token. Absence is integrity protected
by the token signature and means commitment-only delivery. Presence selects
one coverage and one delivery mode.

An inline current envelope is:

~~~ json
{
  "v": 1,
  "coverage": "current",
  "delivery": "inline",
  "steps": [
    { "proof": "<current proof>", "acceptance": "<current actc>" }
  ]
}
~~~

Every envelope contains exactly `v`, `coverage`, `delivery`, and, when
expanded, `steps`; an introspection descriptor omits `steps`. A `current` step
contains exactly `proof` and `acceptance`, both compact JWS strings. A `path`
step contains exactly those members plus `opening` as defined in Section
(#view-commitment, use counter). Extra or missing members and wrong JSON types
MUST be rejected.

`current` MUST contain exactly one step. It MUST NOT contain an actor-view
opening. The step acceptance MUST equal the token's `actc` as an exact string.
The proof ActorID MUST be authorized for disclosure and MUST equal the
outermost current ActorID in the token's `act`. A Subset token carrying
`current` evidence therefore MUST include that actor in `act`; hidden
predecessors remain hidden.

An inline path envelope is:

~~~ json
{
  "v": 1,
  "coverage": "path",
  "delivery": "inline",
  "steps": [
    {
      "proof": "<proof A>",
      "acceptance": "<actc A>",
      "opening": {
        "salt": "<salt A>",
        "act": [{ "iss": "https://actors.example/a", "sub": "A" }]
      }
    },
    {
      "proof": "<proof B>",
      "acceptance": "<actc B>",
      "opening": {
        "salt": "<salt B>",
        "act": [
          { "iss": "https://actors.example/a", "sub": "A" },
          { "iss": "https://actors.example/b", "sub": "B" }
        ]
      }
    }
  ]
}
~~~

`path` MUST contain the continuous root-to-current sequence in order. Every
step MUST contain an opening, each proof and acceptance MUST verify, each
`prev` MUST hash the exact preceding acceptance, and the final acceptance MUST
equal token `actc`. The final opened actor-view array MUST equal the complete
`VisibleChain(act)` in the token. This version permits `path` only with
`verified-full`. Subset and Actor-Only recipients can receive `current`
evidence without hidden predecessors; they MUST NOT receive `path` under this
version. They can also receive `disclosed` evidence as defined below.

## Disclosed Actor Evidence {#disclosed-evidence}

An inline envelope for disclosed A and C is:

~~~ json
{
  "v": 2,
  "coverage": "disclosed",
  "delivery": "inline",
  "steps": [
    { "proof": "<proof A>", "acceptance": "<actc A>" },
    { "proof": "<proof C>", "acceptance": "<actc C>" }
  ]
}
~~~

Envelope version 1 permits only `current` and `path`. Envelope version 2
permits only `disclosed`; it does not change actor proof or acceptance version
2. A recipient MUST reject any other version/coverage combination. Support
for one combination MUST NOT imply support for another.

`disclosed` is available with any Verified profile. The token MUST include
`act`, and its outermost ActorID MUST be the current accepted actor. `steps`
MUST contain exactly one original proof/acceptance pair for each occurrence
in `VisibleChain(act)`, in that order. Each entry contains exactly `proof`
and `acceptance`, both compact JWS strings. Actor-view openings, hidden-actor
entries, and extra entry members MUST NOT be included. The final acceptance
MUST equal token `actc` exactly. Repeated ActorIDs represent separate actor
occurrences; duplicate acceptance artifacts MUST be rejected.

By issuing an inline token with this envelope, the AS attests that every
selected record is an occurrence on the accepted predecessor path ending at
that exact `actc`, in the disclosed order. For introspection delivery, the
issuer makes the same attestation through its authorized response for the
exact token. Equality of `acti` alone is insufficient for AS selection.

Before delivery, the issuing AS MUST establish membership and ordering from
authoritative accepted path state, authenticated preservation state from a
trusted source AS, or validated retained predecessor records. It MUST validate
each selected original proof/acceptance binding and match it to the disclosed
occurrence. Records from a sibling branch or another workflow MUST NOT be
substituted. If the AS cannot establish the association, retain the required
records, or satisfy disclosure policy over their complete contents, it MUST
reject required `disclosed` delivery. It MUST NOT fabricate, rewrite, or
redact an original signed record.

The token signature protects the inline occurrence-to-record mapping. For
introspection, the recipient MUST use the authenticated issuer's authorized
endpoint and require the expanded evidence for that exact token. The recipient
verifies selected original signatures and acceptances; it trusts the issuer's
path-membership assertion. Gaps do not imply adjacency, missing signatures do
not imply absence, and hidden actor verification is not required. A policy
requiring independent full-path membership instead requires `path` with Full
disclosure. Section (#disclosed-validation, use counter) defines recipient
validation.

## Introspection Delivery {#evidence-introspection}

For introspection delivery, token `acte` contains only the version, coverage,
and delivery members. A `current` example is:

~~~ json
{ "v": 1, "coverage": "current", "delivery": "introspection" }
~~~

The authorized RFC 7662 [@!RFC7662] response for that exact token contains
`active=true` and an `acte` member containing the expanded envelope with
`v`, `coverage`, `delivery`, and `steps`.
`steps` uses the same schema and validation algorithm as inline delivery. An
inactive response, unauthorized caller, unavailable endpoint, mismatched
coverage, malformed evidence, or incomplete path fails the requirement.

For disclosed introspection delivery, the token envelope contains exactly
`v=2`, `coverage=disclosed`, and `delivery=introspection`, without `steps`.
The active response supplies the corresponding expanded envelope using the
same selected-record schema, limits, and validation rules. Delivery does not
change the assurance model.

# Transition State Machine {#state-machine}

For Verified profiles, implementations MUST process exactly the following
transitions. Declared profiles retain the corresponding workflow transitions
without actor proofs or acceptances, as specified in Section
(#declared-processing, use counter).

| Transition | Predecessor | Actor proof | New `actc` | State result |
| --- | --- | --- | --- | --- |
| `root` | bootstrap context | required | required | starts `acti` |
| `extend` | validated profiled token | required | required | appends current actor |
| `preserve` | validated protected state | forbidden | forbidden | exact protected state retained |

For `root`, the AS authenticates the actor, allocates `acti` and `sub`,
authorizes a target bound in a short-lived bootstrap context, validates the
root proof and opening, atomically reserves the replay key, durably finalizes
the exact `actc`, applies disclosure policy, and issues the token.

For `extend`, the AS validates the inbound token and current `actc`, verifies
that the authenticated actor was an intended recipient of the inbound token,
validates the extend proof and opening, checks exact predecessor linkage and
authority narrowing, atomically reserves the replay key, appends the actor,
durably finalizes the exact new `actc`, applies disclosure and evidence
requirements, and issues the successor token.

For `preserve`, the AS validates the inbound cross-domain grant, creates no
actor step, preserves protected Actor Chain state exactly, applies only
authorized identity/target translations, and issues a local token or rejects.
A preserve operation MUST NOT be represented as actor participation.

# Bootstrap And Token Exchange {#exchange}

## Verified Bootstrap {#verified-bootstrap}

The initial actor sends an HTTPS `POST` to the authenticated metadata's
`actor_chain_bootstrap_endpoint`. The UTF-8 request body uses
`application/x-www-form-urlencoded` as in RFC 6749 Appendix B [@!RFC6749].
It contains one `actor_chain_profile`, one `resource`, and optional `scope`.
Repeated parameters MUST be rejected. The actor MUST authenticate using a
client-authentication method authorized by the AS for its token endpoint;
this endpoint does not introduce another actor-authentication mechanism.

The AS authenticates the actor, authorizes the profile and target, allocates
`acti` and the workflow `sub`, and creates a short-lived opaque context. A
successful response uses HTTP `200` and `application/json`, with
`Cache-Control: no-store` and `Pragma: no-cache`. It contains the opaque
`actor_chain_bootstrap_context` string and the required
`actor_chain_bootstrap_binding` object. For example:

~~~ json
{
  "actor_chain_bootstrap_context": "<opaque redemption context>",
  "actor_chain_bootstrap_binding": {
    "actor": { "iss": "https://actors.example/a", "sub": "A" },
    "acti": "<workflow identifier>",
    "actp": "verified-full",
    "sub": "<workflow subject>",
    "accepting_issuer": "https://as1.example",
    "target_context": {
      "resource": "https://api.example/", "scope": "read"
    },
    "expires_in": 60
  }
}
~~~

The binding object contains exactly the members shown; `target_context.scope`
is optional and has the syntax defined in Section (#target-scope, use counter).
The context string and all identifier strings MUST be non-empty. `actor` is
the authenticated ActorID; `actp` is the requested profile;
`accepting_issuer` equals the authenticated metadata issuer; `target_context`
contains the exact resource and maximum authorized lexical scope set. For a
Verified bootstrap, that maximum MUST be a lexical subset of the bootstrap
request's scope; omitted bootstrap scope denotes the empty set.
`expires_in` is a positive integer lifetime in seconds from response generation;
a lifetime of at most 60 seconds is RECOMMENDED. The AS retains authoritative
expiry and binds the opaque context to every returned value and the
successful authentication. The actor MUST validate the returned identity,
profile, issuer and target before signing. Unknown top-level response members
are ignored; missing or malformed required members cause failure.

The actor creates a `root` proof using those signable bindings and an opening
whose `act` array contains only its own ActorID. It requests an access token
using `grant_type=client_credentials`, the selected `actor_chain_profile`,
`actor_chain_bootstrap_context`, `actor_chain_step_proof`,
`actor_chain_view_opening`, one `resource`, and any explicitly signed `scope`.
It authenticates as the same actor. The proof and request resource MUST equal
the bootstrap resource exactly; requested scope MAY narrow the context's
maximum scope but MUST NOT exceed it. Omitted scope follows Section
(#target-scope, use counter).

The AS MUST bind the request, proof, opening and context to the same actor,
profile, workflow, subject and accepting issuer, enforce the authorized target
and scope, and require first redemption before context expiry. Exact committed
retries follow Section (#replay, use counter), including its rules for a
consumed or expired one-time context. The bootstrap response supplies no access
token and creates no actor acceptance by itself.

Authentication failures follow the applicable RFC 6749 client-authentication
error rules. Other bootstrap errors use an OAuth JSON error response and
HTTP `400`: `invalid_request` for malformed parameters or unsupported profiles,
`invalid_scope` for unacceptable scope, and `invalid_target` as defined in
RFC 8693 [@!RFC8693] for an unacceptable resource. Temporary inability to
provide authoritative state uses HTTP `503` as in Section (#errors, use counter).
Error details MUST respect disclosure policy.

## Verified Extension

An actor extends a workflow by submitting at least:

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
* the inbound access token as `subject_token`;
* `subject_token_type=urn:ietf:params:oauth:token-type:access_token`;
* the immutable `actor_chain_profile`;
* `actor_chain_step_proof`;
* `actor_chain_view_opening`; and
* the applicable OAuth targeting and scope parameters.

The AS MUST perform the `extend` algorithm in Section
(#state-machine, use counter). RFC 8693
`actor_token`, `actor_token_type`, and `may_act` MAY contribute authorization
inputs according to their governing specifications and local policy, but MUST
NOT change Actor Chain identity, continuity, disclosure, or evidence rules.

## Declared Processing {#declared-processing}

Declared profiles use the same bootstrap, target, `acti`, `sub`, disclosure,
and token-validation model, without `actor_chain_step_proof`,
`actor_chain_view_opening`, `actc`, or `acte`. The AS authenticates the current
actor, appends that actor to authoritative workflow state, applies disclosure
policy, and signs the successor token. Declared root issuance uses the same
authenticated bootstrap response and context redemption, but omits the proof
and opening. Declared tokens MUST NOT contain `actc` or `acte`. A recipient
MUST describe such state as AS-declared, not actor-verified.

# Disclosure Processing {#disclosure}

The AS is the disclosure policy decision and enforcement point. No claim,
identifier, error, evidence envelope, or auxiliary encoding may reveal more
actor-chain information than the selected profile permits.

* **Full:** `act` is REQUIRED and MUST equal the complete accepted actor path.
* **Subset:** `act` MAY be omitted. If present, it MUST be an ordered
  subsequence of the accepted actor-visible chain authorized for that
  recipient. A non-contiguous subset such as `[A,C]` does not assert that A
  directly preceded C. When `current` or `disclosed` evidence is present, `act` is REQUIRED
  and MUST include the directly proved current actor.
* **Actor-Only:** `act` is REQUIRED and MUST contain exactly the current actor.
  No prior actor may be disclosed in the token or `current` evidence.
  `disclosed` evidence MUST likewise contain only that current actor.

The current actor validates that returned disclosure does not exceed what it
was authorized to know. A recipient authorizes using only the actors actually
disclosed to it. Omission does not assert absence.

The actor-view commitment prevents a transported current proof from exposing
the clear chain the actor knew. It does not conceal the current actor, target,
scope, accepting AS, workflow identifier, or timing carried in that proof.

For `disclosed` delivery, the AS MUST apply recipient disclosure policy to
all contents of every selected signed record, including historical targets,
subject identifiers, issuers, times, and predecessor digests. Omitting an
ActorID from `act` does not ensure that a historical target hides the same
service. If a required record conflicts with privacy policy, issuance fails;
the AS MUST NOT silently omit that record or downgrade required coverage.

# Protected Resource Evidence Requirements {#resource-metadata}

A protected resource advertises its Actor Chain evidence floor through OAuth
2.0 Protected Resource Metadata [@!RFC9728]. The provisional extension is:

~~~ json
{
  "resource": "https://api.example/",
  "authorization_servers": ["https://as.example"],
  "actor_chain_evidence_required": {
    "v": 1,
    "coverage": "current",
    "delivery": ["inline", "introspection"]
  },
  "dpop_bound_access_tokens_required": true
}
~~~

Absence of `actor_chain_evidence_required` means commitment-only Verified
tokens are acceptable from the perspective of this specification. Presence
requires the exact coverage and one listed delivery mode. A client preference
does not weaken this authenticated resource requirement.

The `v` and `coverage` pair MUST be one defined in Section
(#evidence, use counter). A resource requiring the original signatures of all
disclosed actor occurrences advertises `v=2` and `coverage=disclosed`, with
its permitted delivery modes. Actor identity requirements remain authenticated
application policy; this metadata does not expose hidden actors or define a
general policy language. A recipient MUST reject missing locally required
actors or evidence. Verification by another recipient does not replace a
local requirement unless explicit local policy authorizes that trust.

When a resource receives no token or an insufficient token, it MAY use the RFC
9728 `WWW-Authenticate` `resource_metadata` parameter to direct the client to
its metadata. An evidence-specific diagnostic MUST NOT become an
unauthenticated alternative source of policy and MUST NOT reveal hidden actors.

A resource that bases authorization on the immediate actor being the live
presenter MUST also require sender-constrained presentation that binds the
issued token to a key controlled by that authenticated actor. DPoP [@!RFC9449]
is the concrete interoperable realization defined here: the AS binds the
current actor and proof-of-possession key during issuance, the token carries
`cnf.jkt`, and the resource validates the DPoP proof, access-token hash, and JWK
thumbprint [@!RFC7638]. Another standardized sender-constraining mechanism MAY
be used by agreement only when it provides an unambiguous token-to-key binding,
the AS binds that key to the same authenticated current actor, and the resource
validates possession on presentation. Client authentication or a protected
transport channel alone does not establish this property.

# Authorization Server Metadata {#as-metadata}

An AS publishes the following RFC 8414 [@!RFC8414] metadata:

~~~ json
{
  "actor_chain_bootstrap_endpoint":
    "https://as.example/actor-chain/bootstrap",
  "actor_chain_capabilities": {
    "profiles": [
      "declared-full", "declared-subset", "declared-actor-only",
      "verified-full", "verified-subset", "verified-actor-only"
    ],
    "proof_versions": [
      2
    ],
    "commitment_versions": [
      2
    ],
    "evidence_versions": [
      1, 2
    ],
    "coverage": ["current", "path", "disclosed"],
    "delivery": ["inline", "introspection"],
    "limits": { "max_depth": 10, "max_inline_bytes": 32768 }
  },
  "identity_chaining_requested_token_types_supported": [
    "urn:ietf:params:oauth:token-type:actor-chain-preserve"
  ]
}
~~~

`actor_chain_bootstrap_endpoint` is the URL of the endpoint defined in Section
(#verified-bootstrap, use counter). An AS supporting Actor Chain root
issuance, including Declared profiles, MUST advertise this endpoint. The
`actor_chain_capabilities` value is a JSON object whose members advertise the
supported profiles, artifact versions, evidence coverage and delivery modes,
and issuance limits shown above. An implementation MUST ignore unknown members
of that object unless another specification defines otherwise.

Clients MUST verify the metadata `issuer` and MUST NOT assume an omitted
capability. The `limits` object is informational about advertised issuance
limits; every participant still enforces its own configured acceptance limits.

An AS advertising `disclosed` MUST advertise evidence version 2. Version 1
support covers only advertised `current` and/or `path`; version 2 support
covers only `disclosed`. Clients MUST select the exact supported version and
coverage required by authenticated resource policy. A legacy version 1
implementation rejects version 2 rather than accepting reduced evidence.

# Validation {#validation}

## Common Token Validation

Before Actor Chain processing, a recipient, actor, or AS MUST validate token
syntax, signature, issuer, audience, expiry, and applicable sender constraint.
It then validates `actp`, `acti`, required claims, disclosure shape, and local
resource limits. An access token signature alone does not validate a nested
proof or `actc`.

For a Verified token, the participant MUST validate `actc` as a compact JWS
with the closed acceptance header and payload schema, using a key authorized
for its trusted `iss` at `accepted_at`. It MUST require acceptance `acti` and
`actp` to equal the token values, enforce the `root`/`extend` rules for `prev`,
and reject an `accepted_at` later than token `iat` beyond permitted clock skew.
The acceptance issuer need not equal the token issuer after preservation.
Without the actor proof, this check authenticates only the AS assertion; it
does not validate `step_hash`, predecessor continuity or the actor signature.
Declared tokens MUST NOT carry `actc` or `acte`.

## Current Evidence Validation

To validate `current`, a recipient MUST:

1. validate the access token and authenticated resource requirement;
2. obtain the expanded evidence inline or from authorized RFC 7662
   introspection of that exact token;
3. require exactly one step and no opening;
4. require exact equality of the step acceptance and token `actc`;
5. take the expected ActorID from the validated token `act`, then validate the
   proof signature using a key independently authorized for that exact ActorID
   at `iat`;
6. require the proof ActorID to equal the outermost current ActorID disclosed
   in the validated token `act`;
7. validate the acceptance signature using a key authorized for the
   actor-signed `accepting_issuer` at `accepted_at`;
8. require matching `v`, `kind`, `acti`, `actp`, `prev`, accepting issuer,
   permitted `iat` to `accepted_at` relationship, and
   exact `step_hash`;
9. require proof and acceptance `acti` and `actp` to equal the token values;
   require proof `sub` to equal token `sub` within one accepting-AS subject namespace, or
   validate an explicitly authorized cross-domain subject mapping when aliases
   differ. Preservation does not require the original acceptance issuer to
   equal the issuer of the current access token;
10. require `target_context.resource` to equal the authenticated RFC 9728
   resource identifier and require token scope to be a lexical subset of proof
   scope; token audience was independently validated in step 1; and
11. validate sender-constrained presentation when authorization relies on the
    immediate actor.

The result directly proves only the current actor. For `extend`, matching `prev` shows actor and AS agreement on a predecessor digest; `current` does not carry or verify that predecessor.

## Path Evidence Validation

To validate `path`, a recipient performs common token validation, obtains the
expanded evidence for that exact token, and then MUST:

1. require `actp=verified-full` and exactly one step per occurrence in the
   token's non-empty `VisibleChain(act)`;
2. require the first step to be `root` with no `prev` and its opening's
   `act` array to contain exactly one entry, the root proof's ActorID;
3. require every later step to be `extend` and each proof and acceptance
   `prev` to equal SHA-256 of the exact preceding compact acceptance;
4. validate every proof and acceptance using the signature, schema, and
   proof/acceptance consistency checks in current validation. Match each
   proof's ActorID to the corresponding `VisibleChain(act)` occurrence and use
   that ActorID for its event-time key authorization. Historical steps are
   not compared to the outermost current actor;
5. validate every actor-view commitment against its opening. Each opening's
   `act` array after the root MUST equal the preceding opening's `act` array
   followed by exactly that step's authenticated proof ActorID;
6. require the final opened array to equal the token's complete
   `VisibleChain(act)`;
7. require every proof and acceptance to carry the token's `acti` and `actp`;
   require `sub` continuity within one accepting-AS subject namespace and an
   explicitly authorized cross-domain mapping when aliases differ, including between the
   final proof and the token. Such mappings are AS-mediated, not directly
   actor-proven;
8. validate every target context, apply the resource and scope comparison in
   current validation to the final step, and do not compare different hops'
   resource identifiers as if they had subset semantics;
9. require the final acceptance to equal token `actc` exactly; and
10. validate sender-constrained presentation when authorization relies on the
    immediate actor.

Path validation proves one disclosed root-to-current accepted path. It does not
prove that no sibling path exists.

## Disclosed Evidence Validation {#disclosed-validation}

To validate `disclosed`, a recipient MUST:

1. perform common token validation and validate the authenticated evidence
   requirement, including the trusted issuer and version/coverage combination;
2. obtain the exact expanded `v=2`, `coverage=disclosed` envelope inline or
   from authorized introspection of that exact token;
3. require a Verified profile, a non-empty `act`, exactly one pair per
   `VisibleChain(act)` occurrence, no openings or extra entry members, and
   all configured byte, step, signature, issuer, and key-lookup limits;
4. match each proof's ActorID to the corresponding disclosed occurrence and
   validate its signature with a key independently authorized for that exact
   ActorID at the signed `iat`;
5. validate each original acceptance signature with a key authorized for its
   actor-signed `accepting_issuer` at `accepted_at`; check the proof and
   acceptance schemas, event-time relationship, exact `step_hash`, and matching
   `kind`, `acti`, `actp`, `prev`, and accepting issuer;
6. require every selected proof and acceptance to carry the token's `acti`
   and `actp`; require proof `sub` continuity within one accepting-AS subject
   namespace and an explicitly authorized cross-domain subject mapping when
   aliases differ, including between the final proof and token `sub`. Such
   mappings are AS-mediated, not directly actor-proven;
7. reject repeated acceptance artifacts and more than one selected root;
   if a root is present, require it to be the first selected record. A selected
   entry's predecessor need not equal the preceding disclosed acceptance:
   omitted occurrences can create a gap. The recipient MUST NOT infer
   adjacency or require hidden actor records;
8. validate each historical target and scope's syntax without comparing
   different hops' targets to the current resource. Apply current-evidence
   target and scope comparisons to the final step, require its ActorID to equal
   the outermost current `act` ActorID, and require its acceptance to equal
   token `actc` exactly;
9. accept selected-record membership and order only as the authenticated
   issuer's attestation for this token and head. A valid selected signature
   alone MUST NOT be treated as independent proof of path membership; and
10. apply local authorization and evidence policy, and validate sender-bound
    presentation when relying on the immediate actor as the live presenter.

Successful validation authenticates every disclosed actor's original signed
request and AS acceptance. It does not validate undisclosed actor signatures,
the complete hidden predecessor chain, original actor-view openings, absence
of sibling branches, or business approvals. Each authorized recipient may
receive a different subset and independently validate that subset.

## Authorization Using Disclosed Evidence {#evidence-authorization}

A recipient recognizing this profile MAY apply configured actor conditions
to records authenticated through the top-level `acte` extension. It MUST
complete the relevant evidence algorithm and normal OAuth subject, audience,
scope, lifetime, and sender checks before using such records. Historical
nested `act` identities without the required authenticated evidence MUST NOT
be promoted to actor-verified authorization inputs. For `disclosed`, local
policy MUST explicitly permit issuer-attested path membership. A policy
requiring independently checked complete membership requires `path` and Full
disclosure instead.

The recipient MUST NOT derive permission from an undisclosed actor, infer that
an omitted actor was absent, or accept a missing locally required actor merely
because another recipient may have verified it. Actor signatures authenticate
the signed protocol request; they do not grant OAuth scope, assert application
roles, or constitute approval of a business artifact. Issuance and application
policy remain responsible for those decisions. These rules define use of the
new top-level evidence extension; they do not change the informational meaning
of earlier nested `act` under RFC 8693.

## Returned-Token Validation

The current actor MUST validate that the AS returned the requested `actp`,
preserved `acti` and `sub`, applied the selected disclosure rules, issued for
the exact proof-bound resource without broadening scope, and returned the
expected `actc`. If the
resource requires evidence, the actor SHOULD confirm that the returned `acte`
posture can satisfy that requirement before presenting the token.

# Cross-Domain Preservation {#cross-domain}

Cross-domain preservation uses OAuth Identity and Authorization Chaining
Across Domains [@!I-D.ietf-oauth-identity-chaining] rather than a parallel Actor
Chain exchange flag.

The source-domain AS performs RFC 8693 Token Exchange targeted to the
destination AS and requests the provisional token type:

~~~ text
urn:ietf:params:oauth:token-type:actor-chain-preserve
~~~

The resulting JWT authorization grant is used at the destination AS as defined
by [@!RFC7523] and the Identity Chaining specification. Its ordinary JWT claims
include `iss`, `sub`, `aud`, `iat`, `exp`, and `jti`. Its Actor Chain protected
state includes exact `actp` and `acti`, plus `actc` and any carried `acte` in
Verified profiles. Declared grants MUST NOT carry `actc` or `acte`. An
introspection descriptor MUST remain unchanged; it is not expanded inside the
grant. Evidence custody needed to satisfy that descriptor MUST be established
through authorized source introspection or a separately authenticated AS-to-AS
mechanism. This specification does not define a separate custody-transfer
encoding. If the destination AS cannot obtain and serve the required evidence
for its issued token, it MUST reject preservation.

Disclosure remains profile-controlled during preservation. Full and
Actor-Only `act` values MUST be preserved exactly. A Subset `act` MAY be
preserved or further narrowed to an ordered subsequence but MUST NOT be
broadened. An omitted `act` MUST NOT be reconstructed from hidden state.

When `current`, `disclosed`, or `path` evidence is carried or referenced, the
corresponding `act` MUST be preserved exactly so that coverage and occurrence
bindings remain valid. A Subset `act` may be narrowed during `preserve` only
when no `acte` is carried or referenced. A later ordinary
`extend` can apply a different authorized Subset disclosure; `preserve` MUST
NOT silently filter the protected evidence or rewrite its signed records.

Identity Chaining permits claims transcription. This Actor Chain token type is
a narrow profile of that behavior: the source and destination AS MUST NOT add,
remove, alter, or normalize the protected state. `actp`, `acti`, and any
carried `actc` require exact value equality, and every compact proof or acceptance string in
`acte` MUST be preserved byte-for-byte. Re-serializing the enclosing JSON does
not change those values. Ordinary identity and authorization claims MAY be
transcribed only as the enclosing protocol and local policy allow. The
destination AS MUST reject if it cannot validate and preserve the protected
state or cannot satisfy the authenticated destination resource's evidence
requirement.

A preserve transition creates no proof and no acceptance. A later actor under
the destination AS performs a normal `extend`; its proof hashes the exact
foreign `actc`, and the destination AS creates one new local `actc`. Path
evidence therefore retains original signer provenance:

~~~ text
proof_A / actc_A  signed by A / AS1
proof_B / actc_B  signed by B / AS2
proof_C / actc_C  signed by C / AS3
~~~

An AS cannot synthesize missing historical path evidence after the relevant
proofs or openings have been discarded. If a later resource may require path
coverage, the required evidence must be retained and preserved across every
boundary. Failure is preferable to silent downgrade or privacy-violating
reconstruction.

The same custody requirement applies to selected originals needed for
`disclosed`. An AS-to-AS exchange must establish accepted-path membership
from authenticated preserved state or retained predecessor records before a
destination AS attests a new selection. No recipient is required to receive
hidden state for this purpose. Lack of authoritative association or authorized
evidence custody causes rejection when selected evidence is required.

Subject, audience, resource, or scope translation is a separate trust
boundary. Audience mappings are AS-local and are not copied into actor proofs.
A destination AS MAY use an authorized and auditable subject, target, or scope
mapping, but MUST NOT describe the mapping as actor-proven semantic
equivalence. Unknown mappings are rejected. An authorized mapping does not
relax recipient evidence validation. When direct evidence is required, the
preserved final proof MUST still satisfy the destination resource's exact
resource and lexical-scope comparisons. A mapping that cannot satisfy those
comparisons requires a fresh authorized `extend` and actor proof; otherwise
preservation MUST be rejected.

Preservation never rewrites a historical proof's `resource` or `scope`. A
later actor may make a normal `extend` transition only by signing a fresh proof
over that transition's exact local resource and scope. That proof can establish
`current` coverage for the new actor and local values; it does not make
earlier actors' signatures attest to those local values. If the destination AS cannot authorize the transition, it
MUST reject. For a later ordinary `extend`, the AS MAY issue commitment-only assurance
when historical evidence is unavailable only if both the authenticated resource
requirement and local policy permit that posture; otherwise it MUST reject.
This option does not permit a `preserve` transition to remove or alter carried
protected `acte`. Inability to preserve required evidence causes rejection. Resource URIs at different hops are not required to
be equal or lexically nested.

# Replay, Retry, And Fan-Out {#replay}

The accepting AS MUST enforce input-size limits and authenticate the current
requester before consulting replay state. Before reserving a previously absent
key, it MUST also complete signature, predecessor, target, authority, opening,
freshness, and other semantic checks. It then enforces atomic uniqueness of:

~~~ text
(accepting_issuer, actor.iss, actor.sub, acti, request_id)
~~~

Malformed, unauthenticated, unauthorized, or otherwise invalid input MUST NOT
consume this key. A previously absent key can be accepted only while the proof
is fresh. The AS MUST create a durable pending record binding the key to the
exact proof, or its SHA-256 `step_hash`, using one linearizable replay-state
operation.

The AS then creates `actc` and atomically finalizes the record with that exact
compact artifact before returning success. A computed but uncommitted `actc`
MUST NOT be returned. A different proof at the same key MUST be rejected even
while the winner is pending. Identical concurrent requests MUST converge on at
most one committed `actc`; other workers return that artifact after commit or
fail without returning success. Crash takeover MUST fence stale workers so
they cannot finalize or emit a different result.

An exact retry matched by a retained committed record is idempotent and reuses
the exact stored `actc`; it does not create a new acceptance. The AS MAY rely
on the committed record for an originally valid one-time bootstrap context or
grant that the first request consumed. It SHOULD return the original success
response. If it instead issues a new token carrying the same Actor Chain state,
the token MUST NOT have broader authority, evidence, or an authorization
horizon later than the original response. The AS MUST still authenticate the
current request and apply current token-issuance, target, sender-constraint,
disclosure, evidence, and authorization policy. Failure of a current check
rejects the request without changing the committed record. Because no new
acceptance occurs, the original proof need not remain fresh at retry time.

Replay state MUST be durable and linearizable across the AS deployment. After
success has been returned, failover MUST NOT expose state older than that
commit. A node that cannot consult or durably update authoritative replay state
during partition or failover MUST NOT return success.

The AS MUST retain the key, proof-match value, exact `actc`, and the response
state needed to enforce the preceding retry limits through the later of the
proof acceptance interval, including clock-skew allowance, and the
deployment's maximum supported exact-retry delay measured from first
acceptance. Retention MUST NOT slide on retry. The supported retry delay SHOULD
be at least the proof acceptance window plus permitted clock skew. After this
state expires, idempotent retry is no longer guaranteed and ordinary proof
freshness still applies. Implementations MAY store fixed-length cryptographic
hashes of replay identifiers to bound storage and reduce raw identifier
exposure.

Distinct `request_id` values MAY create authorized fan-out from one
predecessor. The accepting issuer scopes the replay domain: each AS enforces
the rule for actor transitions it accepts, while `preserve` creates no actor
proof and no Actor Chain transition replay record. Replay handling for the
enclosing grant remains governed by its applicable specifications. This
document does not define branch merging,
sibling enumeration, or proof of branch uniqueness.

# Error And Challenge Handling {#errors}

Token endpoint errors use OAuth [@!RFC6749] and RFC 8693 [@!RFC8693]
error values. This table classifies Actor Chain failures; ordinary OAuth
failures retain the errors defined by their governing specifications.

| Error | Actor Chain condition |
| --- | --- |
| `invalid_request` | malformed Actor Chain parameter or object, unsupported version or type, duplicate JSON member, forbidden profile/transition combination, or configured pre-parsing size limit exceeded |
| `invalid_target` | unacceptable resource, unavailable target mapping, or inability to satisfy that resource's authenticated evidence or sender-constraint requirement |
| `invalid_scope` | requested scope is invalid, unknown, malformed, or not a lexical subset of the accepted actor-authorized scope |
| `invalid_grant` | subject or actor token, bootstrap context, proof, opening, acceptance, predecessor, conflicting replay-key use, disclosure, preserve binding, or actor/sender key validation failure |

Loss of authoritative replay state is not evidence that a grant is invalid.
If the AS cannot consult or durably update that state, or cannot determine
whether an identical pending request committed within its bounded wait, it
MUST return HTTP `503` (Service Unavailable) [@!RFC9110] and MUST NOT return
success or `invalid_grant`. It SHOULD include `Retry-After`. The external
response MUST NOT reveal whether the replay key is absent, pending, or
committed. No Actor Chain-specific OAuth error value is defined for this
condition.

After such a `503`, the requester SHOULD retry the exact token request after
the indicated delay. The compact proof and its signed `request_id` MUST remain
unchanged. A new `request_id` requires a fresh actor proof and represents a
distinct transition that can create authorized fan-out; it MUST NOT be used
merely to recover an uncertain result. If the first request committed, the
exact retry returns the retained success as specified in Section
(#replay, use counter). If it did not commit, ordinary proof freshness still
applies.

A protected resource uses the applicable token authentication scheme and the
RFC 9728 `resource_metadata` challenge parameter to point to its authoritative
metadata. A request without a token uses HTTP `401` and omits an OAuth error as
required by RFC 6750 [@!RFC6750]. A presented token whose Actor Chain evidence
is absent, weaker than required, malformed, or invalid uses the generic
`invalid_token` error and HTTP `401`; the challenge SHOULD include
`resource_metadata` and SHOULD omit `error_description`. Ordinary OAuth scope
insufficiency remains `insufficient_scope` with HTTP `403`; Actor Chain
evidence posture MUST NOT be mislabeled as scope.

For example:

~~~ text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  resource_metadata="https://r.example/m"
~~~

If the resource cannot validate required evidence because an introspection,
key/status, or authenticated-metadata dependency is temporarily unavailable,
it MUST fail closed with HTTP `503`, SHOULD include `Retry-After`, MUST NOT
label the token `invalid_token`, and MUST NOT downgrade the evidence
requirement. The presenter SHOULD retry the same token after the indicated
delay.

An insufficient-evidence challenge can lead the presenter to initiate a fresh
exchange. The AS does not mutate or upgrade the rejected token; it issues a
new token only after revalidating authority, evidence availability, disclosure
authorization, and resource limits.

Error bodies and logs MUST NOT reveal hidden actors, openings, proofs, keys, or
policy details beyond the requesting party's authorized disclosure. They also
MUST NOT reveal which hidden step failed, whether historical evidence exists,
or whether replay state was absent, pending, or committed.

# Resource Limits {#limits}

Implementations MUST enforce configured byte limits before deep parsing,
cryptographic work, decompression, or external retrieval. They MUST also bound
chain depth, evidence steps, protected-header bytes, signatures, distinct
issuers, key lookups, redirects, introspection response bytes, and network
time.

The following defaults are RECOMMENDED starting points, not universal
transport guarantees:

| Limit | Default |
| --- | ---: |
| Actor path depth | 10 |
| One compact Actor Chain JWT/JWS | 32768 bytes |
| Inline Actor Chain access token | 32768 bytes |
| Evidence steps | 10 |
| Nested proof and acceptance signatures | 20 |
| Distinct nested signing authorities | 20 |
| Nested evidence key selections | 20 |
| One decoded protected header | 1024 bytes |
| `request_id` | 128 UTF-8 octets |
| Expanded introspection `acte` object | 32768 bytes |

Local policy MAY use lower limits. Exceeding a limit fails profile processing.
Signature and key-selection limits count nested actor proofs and AS
acceptances; ordinary token and sender-constraint validation are separate
OAuth work. Depth 10 therefore requires 20 nested verifications plus the token
signature. Twenty authorities allow every nested signer to differ without
increasing that work budget.

The 32768-byte ceiling applies both to inline tokens and expanded introspection
`acte`; the entire HTTP message is independently bounded. One validation
attempt MUST NOT make more than one Actor Chain introspection request. Signed
targets are never dereferenced. Key and metadata retrieval use authenticated or
preconfigured endpoints, bounded issuer caches, local redirect and timeout
policy, and the fail-closed behavior in Section (#errors, use counter).

The measured depth-10 Full-path fixture is 23673 bytes inline and 16303 bytes
expanded. These sizes are illustrative; actual sizes depend on identifiers,
scopes and encoding and MUST satisfy configured limits. `actc` and `current` overhead remain
approximately constant for fixed identifier and scope sizes. Full disclosure
and the number of path signatures grow linearly with depth. Because each
path opening repeats the growing actor-view array, aggregate opening size
and processing grow quadratically.

Disclosed evidence work grows with the number of disclosed occurrences, not
with hidden steps. The existing limits apply to it unchanged. The quoted
measurements describe the preceding Full-path fixture, not a measurement of
this newly specified coverage mode.

# JWT, JWS, And Introspection Binding {#bindings}

JWT access tokens SHOULD use `typ=at+jwt`. Actor proofs use
`typ=oauth-act-step+jwt`; AS acceptances use `typ=oauth-actc+jwt`; preserve
grants use `typ=oauth-act-preserve+jwt`.

For Actor Chain proof, acceptance, and preserve JWS objects, the protected
header contains exactly `alg`, `kid`, and `typ`. Implementations of this
specification MUST implement `ES256` [@!RFC7518]. Producers MUST use `ES256`
unless support for another algorithm has been established for every intended
verifier through authenticated metadata, configuration, or prior agreement.
Any additional algorithm MUST be a registered, fully specified asymmetric
signature algorithm [@!RFC9864] that is allowed by current verifier policy.
The deprecated polymorphic `EdDSA` identifier, `alg=none`, and symmetric
algorithms MUST NOT be accepted. This version's interoperability vectors use
`ES256`.

Before processing a signature, the verifier MUST fix the allowed algorithm set
for that `typ`; an attacker-controlled `alg` value cannot enlarge it. Each
trusted key record MUST bind the key to exactly one algorithm, signer identity,
and permitted Actor Chain artifact type. The JWS `alg`, key type, curve or
parameters, and any JWK `alg`, `use`, or `key_ops` restrictions MUST agree.
Implementations MUST use mutually exclusive validation rules for each `typ` as
required by [@!RFC8725].

`kid` is a lookup hint within an issuer-qualified trust namespace, not a global
identity or trust assertion. A verifier resolves the tuple of expected signer,
`kid`, `alg`, `typ`, and applicable event time and MUST reject no match or an
ambiguous match. A key's presence in a JWKS alone does not authorize an ActorID
or AS to sign that artifact type. Signers MUST NOT reuse a `kid` for another
key or signer within the period in which an artifact under the prior key can be
accepted. The closed header excludes attacker-selected key URLs. Network key
resolution MUST use only preconfigured or authenticated issuer metadata and
MUST be bounded and cached by issuer; a verifier MUST NOT dereference an
untrusted issuer or header value.

The closed protected-header set is intentional for proof and acceptance
version 2. An additional protected header, including `crit`, requires a future
version or an update to this specification; it MUST NOT be silently accepted by
a version 2 parser. This rule prevents unreviewed key-selection or processing
semantics from entering the signed-artifact contract.

Proof and acceptance payloads use ordinary UTF-8 JSON. Their linkage hashes
the exact compact JWS strings and therefore does not require whole-payload JCS.
JCS is used for actor-view commitments and the serialized opening request
parameter. JWK thumbprints use the member-selection and serialization rules
of [@!RFC7638]. Parsers MUST reject duplicate members, malformed UTF-8,
base64url padding, unknown payload members, wrong JSON types, non-integer
NumericDate values, and unsupported versions before semantic acceptance.

An RFC 7662 introspection endpoint returning Actor Chain evidence MUST:

* authenticate and authorize the caller for the resource and requested
  evidence;
* process the exact presented token;
* return only evidence the caller is permitted to learn;
* return `active=false` without evidence when the token is inactive or the
  authenticated caller is not authorized to learn state about that token;
* apply the same limits and validation rules as inline evidence; and
* prevent cached evidence from outliving applicable token, revocation, privacy,
  or key-status constraints.

Invalid caller credentials or insufficient endpoint privileges use the
applicable RFC 7662 authentication error, rather than an `active=false`
response. An authorized query for a token the caller is not permitted to
inspect returns `active=false` without evidence.

Availability and latency of introspection are deployment properties. A
resource requiring introspection delivery fails closed when it cannot obtain a
valid response.

# Security Considerations {#security-considerations}

## Assurance Boundaries

A valid `actc` authenticates the AS's assertion that it accepted the referenced
actor proof and, for an `extend` transition, predecessor. Without the proof,
it does not provide direct actor verification. `current` provides
direct verification of the latest proof. `path` provides direct verification
of all disclosed proofs and original AS acceptances on one path.

`disclosed` authenticates the original signatures and acceptances of the
disclosed occurrences, while trusting the issuer's selected-record membership
and order. A malicious issuer can misstate that association, including by
substituting valid records from another branch with the same `acti`. The
recipient's scope, target, current-head, subject, and original-signature checks
still apply, but do not independently prove historical membership across gaps.
This accepted trust boundary is distinct from forgery of an actor signature.

With an uncompromised actor key and an independently authorized ActorID
binding, validation of the actor signature and exact proof-to-acceptance
linkage prevents an AS from fabricating that actor's signed request. This
does not independently establish path membership across omitted steps. An
AS can still mint other tokens, misapply policy, collude with an actor, or lie
about facts outside the signed proof.

## Key History And Compromise

Rotation does not change an existing proof, acceptance, or predecessor hash,
and different steps MAY use different allowed algorithms. Direct verification
still requires issuer-qualified key authorization at the signed event time.
For as long as an artifact can be accepted, the signer or deployment MUST make
available the exact public key and its signer binding, single allowed
algorithm, artifact use, validity interval, status chronology, trust anchor,
and metadata version. Removing a rotated key from the current JWKS, or retaining
only its `kid`, is insufficient. If this historical context is unavailable and
direct evidence is required, validation fails closed.

On suspected compromise, the signer MUST stop using the key and verifiers MUST
apply a consistent locally established cutoff. `iat` and `accepted_at` are
signed assertions, not trusted proof that an artifact predates compromise: a
compromised key can backdate a new artifact. A deployment needing that stronger
claim requires an independently trustworthy timestamp or acceptance record.
Absent such evidence, policy may reject every artifact under the compromised
key. Event-time algorithm policy may support audit interpretation, but it MUST
NOT override a current prohibition on an unsafe algorithm.

## Evidence Custody And Disappearance

Inline evidence can survive later refusal, outage, record loss, or
organizational disappearance if an authorized party retains the token and key
history. Introspection reduces request size and disclosure but introduces a
live service dependency. A digest cannot reconstruct a lost proof.

Deployments promising post-expiry verification MUST retain or export exact
evidence and historical trust context, preferably across independent failure
domains. They MUST NOT describe commitment continuity alone as durable direct
actor verification.

## Target, Scope, And Mix-Up

The actor proof, AS acceptance, issued token, and protected-resource identity
form one target-consistency boundary. Implementations fail closed on accepting
AS substitution, exact-resource mismatch, audience failure, scope widening,
predecessor substitution, profile change, or final-acceptance mismatch. URI
aliases that happen to locate the same service are not equal identifiers for
this purpose. Target strings in proofs are untrusted data for network-access
purposes and MUST NOT drive metadata or content retrieval.

Resource identifiers can reveal service, tenant, path, or query information to
every party receiving direct evidence. Deployments SHOULD use the least
specific stable identifier that still prevents cross-resource or cross-tenant
confusion and SHOULD avoid query components carrying user, session, or business
data.

## Sender Constraint

Actor evidence says which actor signed an authorization transition. It does not
show that the entity now presenting the token controls that actor's live key.
Recipients relying on the immediate actor as the live presenter require
sender-constrained presentation and validate the binding independently.

## Replay State And Availability

Replay atomicity is a safety property across the whole accepting-AS
deployment, not a best-effort cache check. If two partitions independently
accept the same replay key, they can create divergent validly signed `actc`
artifacts. The fail-closed rule therefore trades token-endpoint availability
for unambiguous acceptance during loss of authoritative state. Fencing and
durable commit prevent a crashed or stale worker from releasing a second
result after takeover. These controls do not prove absence of sibling branches
created with different request identifiers.

## Parser And Resource Exhaustion

Path evidence allows attacker-controlled collections of signatures, issuers,
and lookup identifiers. Strict parsing, pre-crypto byte limits, bounded work,
and rejection of unsupported structures are security requirements, not merely
performance optimizations.

## Residual Non-Claims

Actor Chain does not prove application execution, payload safety, human intent,
legal non-repudiation, correctness of authorization policy, absence of hidden
branches, or absence of off-protocol activity. Recipients still perform normal
OAuth authorization and application validation.

# Privacy Considerations {#privacy}

Full path evidence reveals actors, organizations, order, targets, timing, and
stable workflow correlation. It is therefore optional and restricted to Full
disclosure in this version. A resource and AS SHOULD select the minimum
evidence satisfying the resource's authenticated requirement.

`current` evidence contains no actor-view opening and is compatible with
Subset and Actor-Only disclosure. It still reveals the current actor, accepting
AS, workflow identifier, target, scope, and time. `acti` MUST be opaque and
workflow-local. Actor and subject identifiers SHOULD be pairwise or
pseudonymous where possible.

The AS observes the authenticated actor and opening even when the recipient
does not. Evidence stores, replay records, and introspection services therefore
concentrate sensitive relationship and correlation data. Operators MUST
enforce purpose-limited access, encryption, retention limits, disclosure
logging, and audience filtering. Replay records SHOULD be removed when their
required retention ends. Replication for availability MUST NOT silently
broaden disclosure.

A Subset sequence is an ordered subsequence, not proof of adjacency or complete
history. Recipients MUST treat omitted actors as unknown. Selective-disclosure
or encrypted overlays MAY be used by agreement but MUST preserve the base
profile's semantics and must not weaken validation [@RFC9901].

`disclosed` omits actor-view openings but can reveal historical targets, AS
identities, subject aliases, times, and linkable digests. It promises only the
disclosure permitted by the complete-record policy check, not anonymity of
every omitted service. Existing plain JWS records cannot be selectively
redacted. A future SD-JWT proof profile would need its own artifact and hashing
contract; this version reuses original compact JWS records unchanged.

# IANA Considerations {#iana}

This document requests the registrations below. The Change Controller for all
of them is the IETF.

## JSON Web Token Claims Registry

IANA is requested to register the following claims in the "JSON Web Token
Claims" registry established by [@!RFC7519].

| Claim Name | Claim Description | Change Controller | Reference |
| --- | --- | --- | --- |
| `actp` | Actor Chain profile identifier | IETF | Section (#profiles, use counter) |
| `acti` | Actor Chain workflow identifier | IETF | Section (#data-model, use counter) |
| `actc` | Current AS-signed Actor Chain acceptance | IETF | Section (#acceptance, use counter) |
| `acte` | Actor Chain evidence envelope | IETF | Section (#evidence, use counter) |

## OAuth Parameters Registry

IANA is requested to register the following parameters in the "OAuth
Parameters" registry established by [@!RFC6749].

| Name | Parameter Usage Location | Change Controller | Reference |
| --- | --- | --- | --- |
| `actor_chain_profile` | Actor Chain bootstrap request, token request | IETF | Section (#exchange, use counter) |
| `actor_chain_bootstrap_context` | Actor Chain bootstrap response, token request | IETF | Section (#verified-bootstrap, use counter) |
| `actor_chain_bootstrap_binding` | Actor Chain bootstrap response | IETF | Section (#verified-bootstrap, use counter) |
| `actor_chain_step_proof` | token request | IETF | Section (#exchange, use counter) |
| `actor_chain_view_opening` | token request | IETF | Sections (#view-commitment, use counter) and (#exchange, use counter) |

## OAuth Authorization Server Metadata Registry

IANA is requested to register the following metadata parameters in the "OAuth
Authorization Server Metadata" registry established by [@!RFC8414].

For `actor_chain_bootstrap_endpoint`:

* Metadata Name: `actor_chain_bootstrap_endpoint`
* Metadata Description: URL of the authorization server's Actor Chain
  bootstrap endpoint
* Change Controller: IETF
* Specification Document(s): Section (#as-metadata, use counter) of this
  document

For `actor_chain_capabilities`:

* Metadata Name: `actor_chain_capabilities`
* Metadata Description: JSON object describing the authorization server's
  supported Actor Chain profiles, artifact versions, evidence modes, and
  issuance limits
* Change Controller: IETF
* Specification Document(s): Section (#as-metadata, use counter) of this
  document

The Identity Chaining specification, rather than this document, registers
`identity_chaining_requested_token_types_supported`.

## OAuth Protected Resource Metadata Registry

IANA is requested to register the following metadata parameter in the "OAuth
Protected Resource Metadata" registry established by [@!RFC9728].

* Metadata Name: `actor_chain_evidence_required`
* Metadata Description: JSON object describing the Actor Chain evidence
  coverage and delivery modes required by the protected resource
* Change Controller: IETF
* Specification Document(s): Section (#resource-metadata, use counter) of this
  document

## OAuth Token Introspection Response Registry

IANA is requested to register the following members in the "OAuth Token
Introspection Response" registry established by [@!RFC7662]. These names have
the same semantics whether carried in a JWT access token or returned by an
authorized introspection response.

| Name | Description | Change Controller | Reference |
| --- | --- | --- | --- |
| `actp` | Actor Chain profile identifier | IETF | Section (#profiles, use counter) |
| `acti` | Actor Chain workflow identifier | IETF | Section (#data-model, use counter) |
| `actc` | Current AS-signed Actor Chain acceptance | IETF | Section (#acceptance, use counter) |
| `acte` | Actor Chain evidence envelope | IETF | Sections (#evidence, use counter) and (#bindings, use counter) |

## OAuth URI Registry

IANA is requested to register the following value in the "OAuth URI" registry
established by [@!RFC6755]:

* URN: `urn:ietf:params:oauth:token-type:actor-chain-preserve`
* Common Name: Actor Chain Preserve Token Type
* Change Controller: IETF
* Specification Document(s): Section (#cross-domain, use counter) of this
  document

## Media Types Registry

The following registrations use the standards tree and the template defined by
[@!RFC6838]. The subtype, without the `application/` prefix, is also the
required `typ` value defined in Section (#bindings, use counter).

**Media type: `application/oauth-act-step+jwt`**

* Type name: application
* Subtype name: oauth-act-step+jwt
* Required parameters: N/A
* Optional parameters: N/A
* Encoding considerations: binary; an Actor Chain step proof is a JWS Compact
  Serialization consisting of base64url-encoded protected header, payload,
  and signature segments separated by period (`.`) characters
* Security considerations: Section (#security-considerations, use counter)
* Interoperability considerations: N/A
* Published specification: Section (#step-proof, use counter) of this document
* Applications that use this media type: applications producing or validating
  Actor Chain step proofs
* Fragment identifier considerations: N/A
* Additional information:
  * Deprecated alias names for this type: N/A
  * Magic number(s): N/A
  * File extension(s): N/A
  * Macintosh file type code(s): N/A
* Person & email address to contact for further information: A. Prasad,
  ap1729@gmail.com
* Intended usage: COMMON
* Restrictions on usage: N/A
* Author: A. Prasad, R. Krishnan, D. R. Lopez, and S. Addepalli
* Change controller: IETF
* Provisional registration? (standards tree only): No

**Media type: `application/oauth-actc+jwt`**

* Type name: application
* Subtype name: oauth-actc+jwt
* Required parameters: N/A
* Optional parameters: N/A
* Encoding considerations: binary; an Actor Chain acceptance is a JWS Compact
  Serialization consisting of base64url-encoded protected header, payload,
  and signature segments separated by period (`.`) characters
* Security considerations: Section (#security-considerations, use counter)
* Interoperability considerations: N/A
* Published specification: Section (#acceptance, use counter) of this document
* Applications that use this media type: applications producing or validating
  Actor Chain authorization server acceptances
* Fragment identifier considerations: N/A
* Additional information:
  * Deprecated alias names for this type: N/A
  * Magic number(s): N/A
  * File extension(s): N/A
  * Macintosh file type code(s): N/A
* Person & email address to contact for further information: A. Prasad,
  ap1729@gmail.com
* Intended usage: COMMON
* Restrictions on usage: N/A
* Author: A. Prasad, R. Krishnan, D. R. Lopez, and S. Addepalli
* Change controller: IETF
* Provisional registration? (standards tree only): No

**Media type: `application/oauth-act-preserve+jwt`**

* Type name: application
* Subtype name: oauth-act-preserve+jwt
* Required parameters: N/A
* Optional parameters: N/A
* Encoding considerations: binary; an Actor Chain preserve grant is a JWS
  Compact Serialization consisting of base64url-encoded protected header,
  payload, and signature segments separated by period (`.`) characters
* Security considerations: Section (#security-considerations, use counter)
* Interoperability considerations: N/A
* Published specification: Section (#cross-domain, use counter) of this document
* Applications that use this media type: applications producing or validating
  Actor Chain preserve grants
* Fragment identifier considerations: N/A
* Additional information:
  * Deprecated alias names for this type: N/A
  * Magic number(s): N/A
  * File extension(s): N/A
  * Macintosh file type code(s): N/A
* Person & email address to contact for further information: A. Prasad,
  ap1729@gmail.com
* Intended usage: COMMON
* Restrictions on usage: N/A
* Author: A. Prasad, R. Krishnan, D. R. Lopez, and S. Addepalli
* Change controller: IETF
* Provisional registration? (standards tree only): No

# Worked Token Examples {#examples}

Assume `A -> B -> C -> D`, where C is the live presenter to protected resource
D. The JSON below consists of excerpts and illustrative placeholders, not
complete deployable tokens. Required claims omitted from an excerpt remain
required by the data model; cryptographic artifacts and openings are shown
symbolically.

## Commitment-Only Actor-Only

~~~ json
{
  "iss": "https://as3.example",
  "sub": "workflow-subject-alias",
  "aud": ["https://d.example"],
  "scope": "payments.read payments.submit",
  "actp": "verified-actor-only",
  "acti": "workflow-7",
  "act": { "iss": "https://actors.example/c", "sub": "C" },
  "actc": "<actc_C>",
  "cnf": { "jkt": "<C presenter-key thumbprint>" }
}
~~~

D validates AS3's token and `actc` but does not directly validate proof C.
This is the smallest Verified posture and discloses no predecessor.

## Current Actor Evidence

~~~ json
{
  "actp": "verified-actor-only",
  "acti": "workflow-7",
  "act": { "iss": "https://actors.example/c", "sub": "C" },
  "actc": "<actc_C>",
  "acte": {
    "v": 1,
    "coverage": "current",
    "delivery": "inline",
    "steps": [
      { "proof": "<proof_C>", "acceptance": "<actc_C>" }
    ]
  },
  "cnf": { "jkt": "<C presenter-key thumbprint>" }
}
~~~

D validates C's signature, AS3's acceptance, the target and scope bound by C,
and C's live DPoP presentation. The proof contains a commitment to C's
actor-visible history but no opening, so B remains hidden.

## Full Path Across Three Authorization Servers

~~~ json
{
  "actp": "verified-full",
  "acti": "workflow-7",
  "actc": "<actc_C>",
  "acte": {
    "v": 1,
    "coverage": "path",
    "delivery": "inline",
    "steps": [
      { "proof": "<proof_A>", "acceptance": "<actc_A>",
        "opening": "<opening_A>" },
      { "proof": "<proof_B>", "acceptance": "<actc_B>",
        "opening": "<opening_B>" },
      { "proof": "<proof_C>", "acceptance": "<actc_C>",
        "opening": "<opening_C>" }
    ]
  }
}
~~~

AS1 signed `actc_A`, AS2 preserved it and later signed `actc_B`, and AS3
preserved that state and later signed `actc_C`. D validates every original
signature and exact predecessor hash. No AS is allowed to rewrite another
signer's artifact during preservation.

## Introspection Delivery

The access token's `acte` member contains only the following descriptor:

~~~ json
"acte": { "v": 1, "coverage": "current",
          "delivery": "introspection" }
~~~

D submits that exact token to the authorized introspection endpoint. A valid
active response returns the same current step that inline delivery would have
carried. If the endpoint is unavailable and D requires this delivery, D
rejects; it does not silently accept commitment-only assurance.

## Subset With Disclosed Actor Evidence

For D, `act` discloses A and C while B is omitted. This token excerpt omits
the normal issuer, subject, audience, scope, lifetime, identifier, and sender
binding fields; a usable token includes them as required above.

~~~ json
{
  "actp": "verified-subset",
  "acti": "workflow-7",
  "act": {
    "iss": "https://actors.example/c",
    "sub": "C",
    "act": { "iss": "https://actors.example/a", "sub": "A" }
  },
  "actc": "<actc_C>",
  "acte": {
    "v": 2,
    "coverage": "disclosed",
    "delivery": "inline",
    "steps": [
      { "proof": "<proof_A>", "acceptance": "<actc_A>" },
      { "proof": "<proof_C>", "acceptance": "<actc_C>" }
    ]
  }
}
~~~

D verifies A's and C's original signatures and acceptances, validates C's
current target and head, and trusts the issuer's assertion that the selected
records belong to this accepted path. It does not request B's proof. Another
authorized recipient can receive B/C, A/B/C, or another permitted subset
including the current actor C, and
apply its own evidence policy. A's historical target may identify B's service;
the AS must check whether that disclosure is permitted before sending A's
unaltered signed record.

A resource needing this contract advertises an evidence requirement with
`v=2`, `coverage=disclosed`, and its permitted `delivery` array. An AS that
supports only version 1 cannot satisfy it and must reject the requested
issuance. A recipient cannot silently accept current-only evidence instead.

# Deployment Choices {#deployment}

The resource starts with the narrowest assurance question it actually needs:

| Resource question | Evidence posture |
| --- | --- |
| Is a trusted AS assertion sufficient? | commitment-only |
| Did this current actor sign the transition, and is it the live presenter? | `current` plus sender constraint |
| Did each disclosed actor sign its accepted request, trusting issuer path membership? | `disclosed`, any Verified profile |
| Did every disclosed actor sign, and did each AS accept, this path? | `path`, Verified Full |

Inline delivery favors availability and independent retention but increases
token and logging exposure. Introspection favors smaller requests and
centralized authorization but adds live dependency and cache policy. Neither
delivery changes what the signatures prove.

One application domain's `manager`, `approver`, or `operator` concept may not
mean the same thing in another domain. Such policy remains with the application
and its authorization systems. Actor Chain standardizes only mechanically
comparable OAuth scope tokens and protocol state.

# Design Rationale {#rationale}

## Why Proofs Are Created At Every Verified Hop

The proof is the only artifact signed by the actor. Creating it at every
Verified transition lets a verifier authenticate the actor's signed request
when it receives the proof and has an uncompromised actor key with an
independently authorized ActorID binding. Selected path membership remains
subject to the issuer-trust boundary described in Section
(#security-considerations, use counter).

## Why Every Token Does Not Carry Every Proof

Actor-signed evidence was already carried in the authors’ original SPICE
draft [@SPICE-ACTOR-CHAIN-00], Sections 4.3.2 and 7.1. This revision restores
that capability through optional `acte` delivery. AS attestation may suffice
for recipient policy; direct actor verification additionally requires
independently trusted actor-key bindings and incurs verification costs.

The number of proofs, acceptances, signatures, and key lookups grows linearly
with path depth. The repeated actor-view arrays in path openings add
quadratic growth in transported bytes and opening processing. Those costs
are justified for some
resources but not all. Separating mandatory creation from optional delivery
retains the stronger property without forcing its privacy and availability
model globally.

## Why Exact Compact Artifacts Are Hashed

Hashing the exact prior `actc` and current proof eliminates a second chain-head
field, per-workflow hash negotiation, and broad canonicalization. A byte change
is visible and cannot be mistaken for the accepted artifact.

## Why Actor-Only Remains Separate From Subset

Actor-Only is a machine-readable maximum-disclosure promise. A Subset result
that happens to contain one actor does not make the same promise and may expose
different subsets to other authorized recipients.

## Why Path Is Full-Disclosure Only

Every path proof needs an opening to validate how the actor-visible chain grew.
Transporting those openings reveals the path. Restricting path to Verified Full
keeps the base rule explainable and prevents a non-contiguous subset from being
misread as an adjacent verified chain. `disclosed` supplies selected original
signatures without openings and relies on issuer-attested membership. A
recipient does not need to verify hidden actors to use that model. Independent
membership across hidden links would require a separately defined mechanism.

## Why Preserve Is Not An Actor Hop

An AS-to-AS format or namespace transition does not mean another application
actor performed work. Treating preservation as a hop would inflate and
misdescribe the actor path.

# Executable Test Vectors And Independent Validation {#executable-validation}

To reduce byte-level ambiguity and improve interoperability confidence, this
specification includes structured examples and explicit failure rules. The
authors retain local test vectors for the preceding current/path contract and
a focused selected-evidence fixture for this revision. Those materials are
not incorporated as external dependencies of this document. This revision's
new coverage mode still requires independent implementation and interoperability
review; preceding test results do not establish those properties for it.

These materials are informative. They do not replace the normative
requirements, independent implementation review, or security analysis. They
provide examples for checking exact-artifact hashing, canonicalization,
linkage, disclosure, rejection, limits, replay, and errors. Implementation
languages used by the package are not part of the protocol contract.

# Implementation Checklist {#checklist}

An implementation claiming conformance should be able to answer yes to each
applicable item:

* Is profile selection explicit and immutable for `acti`?
* Are actor and AS keys authorized for the exact issuer-qualified identity and
  event time?
* Are duplicate JSON members, unknown fields, wrong types, and unsupported
  versions rejected?
* Does `extend` hash the exact prior compact `actc`?
* Is the final resource exactly equal, and is lexical scope equal or narrowed?
* Does `current` omit every actor-view opening?
* Does `disclosed` match every disclosed occurrence in order, omit openings,
  verify all selected signatures, and require exact final-head equality?
* Does the issuer establish selected membership from authoritative accepted
  state, enforce complete-record privacy, and avoid substitution from branches?
* Is `path` continuous, Full-disclosure, bounded, and final-head-equal?
* Does required evidence fail closed on absence or introspection failure?
* Is reliance on the immediate actor as the live presenter sender constrained?
* Do exact retries reuse one committed `actc` while current issuance policy
  still applies?
* Are replay records durable and linearizable, with stale workers fenced and
  unavailable partitions failing closed?
* Does cross-domain handling preserve protected state values and compact
  artifacts without transcription?
* Are byte, depth, signature, issuer, key-lookup, and network limits applied
  before attacker-amplified work?
* Are evidence custody, historical key context, and privacy retention aligned
  with every audit claim made to relying parties?

# Future Work {#future}

Receiver acknowledgments, terminal result receipts, arbitrary suffix or
independently verified selective path membership, branch transparency,
evidence export after token expiry,
and additional discovery or interoperability profiles for sender-constraining
mechanisms are candidates for companion work. They are not required to
implement this base protocol.

# Relationship To RFC 8693 {#rfc8693-comparison}

This section is informative.

| RFC 8693 | This document when `actp` is present |
| --- | --- |
| Nested `act` is a convention | Disclosure shape and interpretation are profile-defined |
| No workflow correlation | `acti` is stable across transitions |
| No append-only algorithm | `root`, `extend`, and `preserve` are explicit |
| Issuer assertion only | Verified profiles add actor proofs and AS acceptances |
| No evidence requirement discovery | RFC 9728 metadata selects optional direct evidence |

# Relationship to Other Work {#related-work}

This section is informative.

Holder-issued chains support delegation without an AS exchange at every step
[@DELEGATE-SD-JWT]. Actor Chain retains AS issuance policy and varies evidence
delivery by resource requirements. These are deployment tradeoffs. SD-JWT
provides selective disclosure of signed fields [@RFC9901]; this version's
selected original JWS evidence does not define a new field-redaction format.

## SD-JWT Composition

This section is informative. SD-JWT [@RFC9901] is a candidate encoding layer
for a future Actor Chain profile, not an implemented alternative wire format
in this specification. Its verified payload could supply profiled token
claims, while unchanged `actc` and selected original JWS records retain their
Actor Chain meanings. A separate actor-signed SD-JWT proof profile could allow
historical field disclosure, but would need explicit proof typing, validation,
and acceptance-hash rules.

Such a profile needs to define required non-disclosable validity claims,
presentation serialization, negotiation, actor-occurrence/evidence matching,
and key binding alongside OAuth sender constraints. SD-JWT key binding does
not automatically replace this specification's DPoP contract. Hiding a middle
node in nested `act` does not automatically produce a valid non-contiguous
Actor Chain subsequence. Holder-selected disclosures must satisfy the
recipient's authenticated evidence floor and the AS's disclosure authorization.
SD-JWT proves integrity of revealed signed fields; it does not itself assign
Actor Chain transition, path-membership, or business-authorization semantics.

# Agent and Workload Integration {#agent-workload-integration}

This section is informative. Actor Chain operates at authorization transitions;
it does not change MCP tool messages, A2A task semantics, or Kubernetes RBAC.
The example is A, an orchestrator, calling B, an A2A planner; B calling C, an
MCP connector; and C calling D, a Kubernetes-hosted API.

| Hop | Authorization integration |
| --- | --- |
| A to B | Obtain a token for B; transmit it using B's advertised A2A security scheme. |
| B to C | Exchange B's inbound token at an authorized AS for a token issued for C's MCP resource. |
| C to D | Authenticate C and exchange its inbound token for D's resource and authorized scope. D or its enforcement gateway verifies the required evidence. |

MCP HTTP authorization specifies Bearer presentation and authenticated
resource discovery [@MCP-AUTH]. A conforming deployment retains resource-specific
tokens instead of forwarding C's inbound MCP token to D. Actor Chain requires
support at the AS, exchange client, and resource verifier; ordinary OAuth
middleware does not implement these extensions automatically. Local MCP
stdio does not use the HTTP authorization flow.

DPoP-bound access tokens use the DPoP authentication scheme. A Bearer-only
MCP transport therefore does not implement this specification's concrete DPoP
presentation merely by adding a proof header. An explicitly agreed RFC 8705
certificate-bound deployment [@RFC8705] can retain Bearer presentation when
the AS associates the certificate key with the authenticated current actor
and the resource verifies its token binding and TLS possession. This is an
application of the existing sender-constraint alternative, not a new
interoperability profile. If metadata requires DPoP, mTLS is not a fallback.
A TLS-terminating gateway needs a trusted certificate-validation boundary;
a forwarded certificate header alone does not establish possession.

A2A advertises security schemes and obtains credentials outside task messages
[@A2A-SPEC]. Its task or context identifier is not `acti`. Polling, streaming,
and token refresh do not automatically create actor steps. Step-up authority
needs fresh authorization; it does not enlarge previously signed scope.

Kubernetes projected service-account tokens can authenticate workloads under
an explicit trust and audience policy [@K8S-SA]. They are issuer-signed
credentials, not actor step signatures or token-to-key bindings. Verified
actors additionally use authorized signing keys with retained event-time
bindings. Shared service identities do not imply distinct pod attribution.
A signing proxy is attributed according to its authenticated identity; its
signature does not become an unmodified application's own signature.

Before signing, clients select the exact resource identifier from authenticated
metadata. Resource-verifier adapters apply the exact signed-resource comparison
even when ordinary URL or audience middleware normalizes equivalent spellings.

An inbound DPoP binding belongs to the actor that presented the token to the
receiving service. Receiving that token does not transfer the sender's private
key. The AS needs an explicitly authorized recipient-exchange policy that
preserves applicable subject-token checks and authenticates the new actor.
Token possession, client authentication, and a new step signature do not prove
possession of the original sender's key. This is a deployment prerequisite to
the example; AS-specific behavior needs integration testing before claiming
end-to-end interoperability.

The Kubernetes API server and its RBAC policy are not implicitly extended by
Actor Chain. Deployment requires explicit application or gateway validation;
workload identity and ordinary cluster auditing do not implement these rules.

{backmatter}

<reference anchor="DELEGATE-SD-JWT" target="https://www.ietf.org/archive/id/draft-gco-oauth-delegate-sd-jwt-00.html">
  <front>
    <title>Delegate SD-JWT</title>
    <author initials="G." surname="Oliver" fullname="Gareth Oliver"/>
    <date month="April" day="21" year="2026"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-gco-oauth-delegate-sd-jwt-00"/>
</reference>

<reference anchor="ACTOR-CHAIN-OVERVIEW" target="https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain-overview/">
  <front>
    <title>OAuth Actor Chain: Overview and Design</title>
    <author initials="A." surname="Prasad" fullname="A Prasad"/>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <author initials="D." surname="Lopez" fullname="Diego R. Lopez"/>
    <author initials="S." surname="Addepalli" fullname="Srinivasa Addepalli"/>
    <date month="October" day="4" year="2026"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-mw-oauth-actor-chain-overview-00"/>
</reference>

<reference anchor="MCP-AUTH" target="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization">
  <front>
    <title>Model Context Protocol Authorization, revision 2026-07-28</title>
    <author><organization>Model Context Protocol</organization></author>
  </front>
</reference>

<reference anchor="A2A-SPEC" target="https://a2a-protocol.org/v1.0.0/specification/">
  <front>
    <title>Agent2Agent Protocol Specification, version 1.0.0</title>
    <author><organization>A2A Project</organization></author>
  </front>
</reference>

<reference anchor="K8S-SA" target="https://kubernetes.io/docs/concepts/security/service-accounts/">
  <front>
    <title>Kubernetes Service Accounts</title>
    <author><organization>Kubernetes</organization></author>
  </front>
</reference>

<reference anchor="RFC8705" target="https://www.rfc-editor.org/rfc/rfc8705">
  <front>
    <title>OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</title>
    <author initials="B." surname="Campbell"/>
    <author initials="J." surname="Bradley"/>
    <author initials="N." surname="Sakimura"/>
    <author initials="T." surname="Lodderstedt"/>
    <date month="February" year="2020"/>
  </front>
  <seriesInfo name="RFC" value="8705"/>
</reference>

<reference anchor="SPICE-ACTOR-CHAIN-00" target="https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/00/">
  <front>
    <title>Cryptographically Verifiable Actor Chain for OAuth 2.0 Token Exchange</title>
    <author initials="A." surname="Prasad" fullname="A Prasad"/>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <author initials="D." surname="Lopez" fullname="Diego R. Lopez"/>
    <author initials="S." surname="Addepalli" fullname="Srinivasa Addepalli"/>
    <date month="February" day="25" year="2026"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-mw-spice-actor-chain-00"/>
</reference>

<reference anchor="OAUTH-ACTOR-CHAIN-01" target="https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/01/">
  <front>
    <title>Cryptographically Verifiable Actor Chains for OAuth 2.0 Token Exchange</title>
    <author initials="A." surname="Prasad" fullname="A Prasad"/>
    <author initials="R." surname="Krishnan" fullname="Ram Krishnan"/>
    <author initials="D." surname="Lopez" fullname="Diego R. Lopez"/>
    <author initials="S." surname="Addepalli" fullname="Srinivasa Addepalli"/>
    <date month="June" day="15" year="2026"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-mw-oauth-actor-chain-01"/>
</reference>
