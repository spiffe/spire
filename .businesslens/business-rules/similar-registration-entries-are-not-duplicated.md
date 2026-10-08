---
appliesTo:
  - type: capability
    id: create-registration-entry
  - type: capability
    id: generate-join-token
references:
  - kind: code
    role: implementation
    target: pkg/server/api/entry/v1/service.go
---

# No two registration entries share parent, SPIFFE ID and selectors

Creating an entry whose parent ID, SPIFFE ID and selectors equal an existing
entry's returns the existing entry instead.
