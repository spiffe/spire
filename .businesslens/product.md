---
id: spire
summary: "SPIRE attests running software and the nodes it runs on, and issues them short-lived SPIFFE identities (X.509-SVIDs and JWT-SVIDs) and trust bundles so they can authenticate each other."
category: workload-identity
tags:
  - spiffe
  - identity
  - attestation
  - federation
  - mtls
  - pki
  - zero-trust
authors:
  - name: The SPIFFE community
    url: "https://github.com/spiffe/spire"
license: Apache-2.0
languages:
  - en
limitations:
  - "Identities are issued only to software that attestation identifies by selectors; SPIRE never issues an identity on a caller's claim alone."
  - Each SPIRE Server serves one trust domain; other trust domains are trusted through federation.
  - "Node and workload attestation, key storage, upstream certificate authorities, persistence, SVID stores and bundle publishing are provided by configured plugins."
  - "SPIRE has no graphical console: it is administered through the server and agent command lines and the Server API."
  - "Server and agent settings come from their configuration files when they start; apart from the logging level, the APIs never change them."
  - "Registration entry expiry is a data management feature, not a security control."
  - Software that receives an identity uses it to authenticate to other systems; those systems decide what it may access.
  - The OIDC Discovery Provider publishes discovery metadata and signing keys only; it has no interactive authorization endpoint.
references:
  - kind: doc
    role: context
    target: README.md
    title: SPIRE README
  - kind: doc
    role: context
    target: doc/SPIRE101.md
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: SPIRE Server configuration and command reference
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: SPIRE Agent configuration and command reference
  - kind: doc
    role: context
    target: doc/scaling_spire.md
    title: "Scaling SPIRE: nested and federated deployments"
---

# SPIRE

SPIRE, the SPIFFE Runtime Environment, establishes trust between software
systems. A SPIRE Server holds the registration entries that say which software
gets which SPIFFE ID, signs identities with its trust domain's authorities,
rotates those authorities, and keeps the trust bundles of its own and
federated trust domains. SPIRE Agents attest the node they run on to the
server, then attest each local process that asks for an identity and hand it
the X.509-SVIDs, JWT-SVIDs and bundles its registration entries entitle it to,
rotating them before they expire. Servers can be nested below one another,
federate with other trust domains through SPIFFE bundle endpoints, and publish
JWT signing keys to OIDC-authenticated systems through the OIDC Discovery
Provider.

## Intent

Software proves who it is from where and how it runs, never from a long-lived
secret someone had to distribute, so two workloads can establish mTLS or
verify a JWT across platforms and trust domains.
