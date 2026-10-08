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
    target: support/oidc-discovery-provider/domain_policy.go
---

# Fetch the discovery document

An OIDC-authenticated system fetches the OpenID Connect discovery document
that names the issuer and where the signing keys are.
