---
availability:
  - place: oidc-discovery-provider
references:
  - kind: code
    role: implementation
    target: support/oidc-discovery-provider/handler.go
  - kind: doc
    role: intent
    target: support/oidc-discovery-provider/README.md
  - kind: code
    role: implementation
    target: support/oidc-discovery-provider/server_api.go
---

# Fetch the signing keys

An OIDC-authenticated system fetches the trust domain's JWT signing keys as a
JSON Web Key Set, which the provider keeps current by polling its key source.
