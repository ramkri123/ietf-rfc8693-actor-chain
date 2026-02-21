%%%
title = "Transitive Attestation for Workload Proof of Residency"
abbrev = "WIMSE-TRANS-ATT"
category = "info"
docName = "draft-mw-wimse-transitive-attestation-00"
ipr = "trust200902"
area = "Security"
workgroup = "WIMSE"
keyword = ["attestation", "wimse", "transitive", "workload identity", "residency"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-wimse-transitive-attestation-00"
status = "informational"

[[author]]
initials = "R."
surname = "Krishnan"
fullname = "Ram Krishnan"
organization = "JPMorgan Chase & Co"
  [author.address]
  email = "ramkri123@gmail.com"

[[author]]
initials = "A."
surname = "Prasad"
fullname = "A Prasad"
organization = "Oracle"
  [author.address]
  email = "a.prasad@oracle.com"

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

This document proposes a mechanism for Transitive Attestation within the Workload Identity in Multi-Service Environments (WIMSE) framework. It addresses the problem of identity portability and the theft of credentials (such as private keys and bearer/DPoP tokens) by requiring workloads to prove "residency"—a verifiable connection to a local, hardware-rooted Workload Identity Agent (WIA).

{mainmatter}

# Introduction

Current workload identity mechanisms, such as DPoP [[RFC9449]], focus on binding tokens to keys but do not necessarily ensure that the workload using the key is the one originally authorized or that it is executing in a verified context. If a private key or an active session token is stolen (e.g., via Remote Code Execution, side-channel attacks, or prompt injection on an AI agent), it can often be used from a different, unverified location or environment.

This proposal introduces "Transitive Attestation" and "Proof of Residency (PoR)". A workload must obtain a fresh signature or proof from a local Workload Identity Agent (WIA) that has already been RATS-verified [[RFC9334]]. This ensures the identity—and the usage of its associated credentials—is hardware-rooted (e.g., via TPM) and sensitive to the physical or logical residence of the workload.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [[RFC2119]] [[RFC8174]] when, and only when, they appear in all capitals, as shown here.

This document leverages the terminology defined in the RATS Architecture [[RFC9334]] and the WIMSE Architecture [[!I-D.ietf-wimse-arch]].

Workload Identity Agent (WIA):
: A local entity that acts as an **Attester** or **Attestation Intermediate** in the RATS framework. It is responsible for providing Evidence or Attestation Results to a workload.

Proof of Residency (PoR):
: A cryptographic proof that binds a workload's current execution session to a specific, verified local environment or host.

# The Problem: Identity and Token Portability

Workload identities are often represented by bearer tokens or keys that, once compromised, can be used by an attacker from any environment. This "portability" allows an attacker who achieves RCE on a workload (e.g., in Region A) to use the stolen keys or intercepted tokens from an attacking machine (e.g., in Region B). Even binding keys to the workload (DPoP) does not prevent the key itself from being exported if the environment is not sufficiently isolated, nor does it prevent a validly generated DPoP token from being replayed from a different VPC if the resource server does not enforce residency.

# The Solution: Transitive Attestation for Proof of Residency

"Transitive Attestation" establishes a chain of trust from a hardware root through a local agent to the workload. The WIA provides the workload with a "live" proof that it is currently resident on the verified host. This local peer-to-peer connection is typically enforced through a **Unix Domain Socket (UDS)**, providing a kernel-level guarantee that the workload is co-located with the hardware-rooted agent.

## mTLS-based Transitive Attestation

In an mTLS environment, the Proof of Residency (PoR) is bound to the mutually authenticated session and the local execution context via a transitive chain of trust.

### mTLS PoR Protocol Flow

The mTLS-based flow integrates residency verification into the session establishment and validation phase:

1. **Certificate Extensions**: The client (workload) supplies an X.509 certificate during the mTLS handshake containing a custom extension. This extension includes the public key or SVID details of the local WIA (Attester).
2. **Post-Handshake Nonce**: After the mTLS handshake is successfully completed, the client requests a residency-specific nonce from the resource server (Verifier/Relying Party) to ensure anti-replay.
3. **Local Attestation Binding**: The client constructs a PoR assertion payload containing:
    - A cryptographic hash of the mTLS session key.
    - The residency nonce provided by the server.
    - A timestamp representing the current time of assertion creation.
4. **Agent Signature**: The client sends this payload to the local WIA (typically via a Unix Domain Socket). The WIA verifies the local peer environment and signs the payload with its private key.
5. **PoR Submission**: The client sends this attested response to the resource server for verification.
6. **Server Verification**: The resource server performs a joint verification of identity and residency:
    - **Identity**: Verifies the client certificate as part of standard mTLS.
    - **Residency**: Verifies the PoR assertion signature against the WIA public key found in the client's certificate extension.
    - **Binding and Freshness**: Ensures that the mTLS session key hash, the nonce, and the timestamp match the current active session and are within an acceptable freshness window.

Upon successful verification, the resource server has proof that the client identity (presented via mTLS) is currently resident in the same authorized environment as the verified WIA.

## DPoR: Demonstrating Proof of Residency

"Demonstrating Proof of Residency" (DPoR) is an enhancement to the Demonstrating Proof-of-Possession (DPoP) mechanism defined in [[RFC9449]]. While DPoP ensures *possession* of a private key held by the client, DPoR ensures the *residency* of the workload using that key by binding the request to a local, hardware-rooted attestation.

### DPoR Protocol Flow

The DPoR flow integrates residency verification into the per-request application-level authorization:

1. **Nonced Request**: The Resource Server SHOULD provide a residency-specific nonce (e.g., via a `DPoR-Nonce` header) to the client to ensure anti-replay of the residency proof.
2. **Local Attestation Binding**: The client constructs a DPoR assertion payload containing:
    - The hash of the DPoP public key used for the request (e.g., the `jkt` thumbprint).
    - The residency nonce provided by the server.
    - A timestamp representing the current time of assertion creation.
3. **Agent Signature**: The client sends this payload to the local WIA (typically via a Unix Domain Socket). The WIA (acting as an Attester) verifies the local execution context and signs the payload with its private key.
4. **DPoR Assertion Submission**: The client includes the resulting signature in a `DPoR` header or as an extension to the `DPoP` JWT.
5. **Server Verification**: The resource server performs a joint verification of possession and residency:
    - **Possession**: Verifies the DPoP proof as per [[RFC9449]].
    - **Residency**: Verifies the DPoR assertion signature against the WIA public key.
    - **Binding and Freshness**: Ensures that the `jkt` (DPoP key thumbprint), the nonce, and the timestamp in the residency proof match the current request and are within an acceptable freshness window.

This binding ensures that a DPoP key cannot be "exported" and used from a different machine, as the resource server would detect the lack of a valid, hardware-rooted residency proof for that specific key from the new environment.

# Relation to Other IETF Work

This proposal builds upon and complements several ongoing efforts in the WIMSE, RATS, and SPICE working groups, forming what can be viewed as a three-layer "Chain of Accountability" that anchors software workloads to physical hardware and geographic locations:

| Layer | Component | Core Responsibility |
| :--- | :--- | :--- |
| **The Mechanism** | **RATS** | Consolidates hardware primitives (TPM, PTP, Geo-sensors) into high-confidence results. |
| **The Policy** | **WIMSE** | (This Draft) Standardizes Transitive Attestation to solve identity portability. |
| **The Shield** | **SPICE** | Employs Selective Disclosure (SD-CWT) to protect residency/geographic privacy. |

1.  **RATS (Remote Attestation Procedures) - The Mechanism**: Provides the hardware-rooted foundation. This layer (leveraging [[RFC9334]]) consolidates primitives like TPM 2.0 (silicon identity), PTP (clock sync/anti-replay), and geo-sensors into High-Confidence Geographic Results.
2.  **WIMSE (Workload Identity in Multi-Service Environments) - The Policy**: Standardizes the Transitive Attestation Profile (this document). It addresses the "identity portability" problem by making SVIDs "sticky" to a specific host's WIA (e.g., SPIRE), ensuring an attacker cannot export a stolen key without also controlling the hardware-rooted agent.
3.  **SPICE (Secure Patterns for Internet Credential Exchange) - The Shield**: Utilizes Selective Disclosure (SD-CWT) to protect sensitive location data. It allows a workload to prove residency within a broad "Sovereign Zone" without revealing precise GPS coordinates, balancing security with privacy.

Additional relationships include:
- **Verifiable Geofencing [[!I-D.lkspa-wimse-verifiable-geo-fence]]**: Provides the framework for geo-fence enforcement. This draft acts as the technical integrator profile that implements these residency proofs within mTLS and DPoP flows.
- **Trustworthy Workload Identity [[!I-D.novak-twi-attestation]]**: Defines the acquisition of credentials based on platform trust. This draft formalizes how that trust is transitively extended to the application-layer identities used in production.
- **DPoP [[RFC9449]]**: This draft proposes DPoR as a "Residency" extension to the "Possession" model of DPoP, addressing the vulnerability where stolen DPoP keys can be used from unverified environments.
- **Service-to-Service Authentication [[!I-D.ietf-wimse-s2s-protocol]]**: Complements S2S flows by adding residency verification to the authentication phase.

# Other Related Efforts

Outside of the IETF, this proposal aligns with several industry standards for secure workload execution:

- **CNCF SPIFFE/SPIRE**: This draft formalizes the application-layer binding for SPIRE's node-to-workload attestation chain. It ensures that the short-lived SVIDs issued by SPIRE are cryptographically bound to the hardware-rooted residency assertion provided by the SPIRE Agent (acting as the WIA).
- **Confidential Computing Consortium (CCC)**: Proof of Residency (PoR) provides the cryptographic evidence required for "Sovereign AI" and "Data-in-Use" protection models. In Confidential Computing (CC) environments, the hardware itself can generate direct, cryptographically signed quotes (e.g., using AMD SEV-SNP VCEK/VLEK keys). These quotes typically include two distinct layers of evidence:
    1.  **Platform Attributes**: Measurements of the processor's identity, microcode version (TCB), and hardware security state.
    2.  **Workload Measurements**: Measurements of the workload's code/memory image and custom metadata (e.g., via the `REPORT_DATA` field).

  While these direct quotes provide high-assurance hardware-direct residency, the **Transitive Attestation** model specified in this document acts as the essential **Identity Bridge**. This bridge can manifest in two architectural patterns:
    1.  **Agent-Mediated Flow**: Traditional in standard environments where a local WIA (e.g., a SPIRE Agent) performs the local attestation and translation before the workload receives its identity.
    2.  **Direct Quoting Flow**: Typical in CC TEEs where the workload performs "Direct Quoting" of the hardware state. In this pattern, the **transitive mapping** from hardware evidence to application-layer identity (SVID) typically occurs at a remote **Verifier/CA** (e.g., a SPIRE Server) during the initial credential issuance phase.

  In both patterns, the result is the same: the high-level application identity becomes cryptographically bound to the hardware-rooted residency, ensuring that Verifiers and Relying Parties do not need to implement complex, vendor-specific measurement verification logic for every diverse hardware platform.

# Security Considerations

Proof of Residency (PoR) specifically mitigates the "Stolen Credential Portability" threat, which encompasses both stolen private keys and stolen bearer/DPoP tokens. 

An attacker who steals a private key or intercepts an active token from a workload cannot use those credentials from an external environment. Any attempt to use the stolen credential requires a corresponding PoR assertion that is:
1.  **Hardware-Rooted**: Linked to the local WIA's signing interface and TPM/Secure Enclave.
2.  **Context-Specific**: Bound to a fresh, server-provided nonce and a current timestamp.
3.  **Protected**: Access to the WIA's signing capability is restricted by local Operating System permissions and logical isolation.

Consequently, credentials become functionally "sticky" to the verified residence; an attacker cannot generate a valid residency proof without achieving a deep compromise of the hardware-protected identity agent itself.

TBD: Discussion on WIA compromise, nonce entropy requirements, and clock skew for timestamp verification.

# IANA Considerations

This document has no IANA actions at this time.

{backmatter}

<reference anchor="I-D.ietf-wimse-arch" target="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch">
  <front>
    <title>Workload Identity in a Multi System Environment (WIMSE) Architecture</title>
    <author initials="Y." surname="Sheffer" fullname="Yaron Sheffer"/>
    <date month="October" day="21" year="2024"/>
  </front>
</reference>

<reference anchor="I-D.ietf-wimse-s2s-protocol" target="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-s2s-protocol">
  <front>
    <title>WIMSE Service to Service Authentication</title>
    <author initials="P." surname="Howard" fullname="Pieter Howard"/>
    <date month="October" day="21" year="2024"/>
  </front>
</reference>

<reference anchor="I-D.lkspa-wimse-verifiable-geo-fence" target="https://datatracker.ietf.org/doc/html/draft-lkspa-wimse-verifiable-geo-fence">
  <front>
    <title>Zero-Trust Sovereign AI: Verifiable Geofencing &amp; Residency Proofs for Cybersecure Workloads</title>
    <author initials="D." surname="Lopez" fullname="Diego Lopez"/>
    <date month="February" day="11" year="2025"/>
  </front>
</reference>

<reference anchor="I-D.novak-twi-attestation" target="https://datatracker.ietf.org/doc/html/draft-novak-twi-attestation">
  <front>
    <title>Remote Attestation for Trustworthy Workload Identity</title>
    <author initials="N." surname="Novak" fullname="Ned Novak"/>
    <date month="July" day="4" year="2024"/>
  </front>
</reference>
