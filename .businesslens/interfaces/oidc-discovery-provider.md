---
type: api
actors:
  - oidc-authenticated-system
references:
  - kind: code
    role: implementation
    target: support/oidc-discovery-provider/handler.go
  - kind: doc
    role: intent
    target: support/oidc-discovery-provider/README.md
---

# OIDC Discovery Provider

A separately deployed HTTPS service that publishes an OpenID Connect discovery
document and the trust domain's JWT signing keys, so systems that authenticate
through OIDC can verify JWT-SVIDs. It reads the keys from the server's local
API, an agent's Workload API, or a bundle file.
