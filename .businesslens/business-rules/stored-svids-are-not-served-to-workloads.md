---
appliesTo:
  - type: capability
    id: fetch-svid
  - type: capability
    id: fetch-secrets
references:
  - kind: code
    role: implementation
    target: pkg/agent/manager/sync.go
  - kind: code
    role: implementation
    target: pkg/agent/svid/store/service.go
---

# Entries marked Store SVID are never served to workloads

The SVIDs of entries marked Store SVID are written by the agent to the SVID
store their selectors name, and removed from it when the entry goes away; they
are not served through the Workload API or Envoy SDS.
