---
appliesTo:
  - type: capability
    id: fetch-svid
  - type: capability
    id: subscribe-to-broker-x509-svids
references:
  - kind: code
    role: implementation
    target: pkg/agent/common/hintsfilter/hintsfilter.go
---

# Of entries sharing a hint, only the oldest is served

When two matching entries carry the same non-empty hint, a workload or broker
receives only the identity of the entry created first.
