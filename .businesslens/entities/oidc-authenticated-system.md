---
kind: system
acts: external
references:
  - kind: doc
    role: context
    target: doc/scaling_spire.md
    title: Federation with OIDC-Provider Systems
---

# OIDC-authenticated system

A remote system outside the trust domain, such as a public cloud provider's
identity federation, that verifies JWT-SVIDs as OpenID Connect tokens using
the discovery document and keys the OIDC Discovery Provider publishes.
