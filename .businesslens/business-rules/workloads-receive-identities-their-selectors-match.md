---
appliesTo:
  - type: capability
    id: fetch-svid
  - type: capability
    id: fetch-secrets
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
---

# A workload receives only the identities whose selectors it matches

The agent attests the calling process into selectors and serves only the
registration entries, among those it is authorized for, whose selectors are
all among them. A caller that matches none gets no identity.
