---
appliesTo:
  - type: capability
    id: fetch-discovery-document
  - type: capability
    id: fetch-signing-keys
references:
  - kind: code
    role: implementation
    target: support/oidc-discovery-provider/domain_policy.go
---

# The discovery document is served only for allowed domains

The OIDC Discovery Provider answers discovery requests only for hosts among
its configured domains; the signing keys are served whatever the host.
