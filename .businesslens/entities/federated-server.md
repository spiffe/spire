---
kind: system
acts: external
references:
  - kind: doc
    role: context
    target: doc/scaling_spire.md
    title: Federation
---

# Federated server

The SPIFFE implementation of a foreign trust domain, typically another SPIRE
Server, that fetches this trust domain's bundle from its SPIFFE bundle
endpoint so its software can authenticate identities issued here.
