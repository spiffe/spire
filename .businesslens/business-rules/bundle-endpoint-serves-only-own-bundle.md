---
appliesTo:
  - type: context
    context:
      place: bundle-endpoint
references:
  - kind: code
    role: implementation
    target: pkg/server/endpoints/config.go
---

# The bundle endpoint serves only the server's own bundle, to anyone

The SPIFFE bundle endpoint does not authenticate its callers and never serves
federated bundles.
