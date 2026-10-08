---
appliesTo:
  - type: capability
    id: sync-authorized-entries
  - type: capability
    id: issue-svid
references:
  - kind: code
    role: implementation
    target: pkg/server/authorizedentries/cache.go
---

# An agent receives only the registration entries it is authorized for

An agent is authorized for the entries parented by its own SPIFFE ID, the
entries parented by a node alias whose selectors are all among its node
selectors, and every entry descending from those through their SPIFFE IDs. It
may have SVIDs signed only for those entries.
