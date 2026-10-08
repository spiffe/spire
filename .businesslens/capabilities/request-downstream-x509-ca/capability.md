---
availability:
  - place: "server-api::downstream"
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/svid/v1/service.go#NewDownstreamX509CA"
  - kind: doc
    role: context
    target: doc/scaling_spire.md
    title: Nested SPIRE
---

# Request a downstream X.509 CA

A downstream server obtains an intermediate CA signed by this server's active
X.509 authority, which it uses as its own X.509 authority.
