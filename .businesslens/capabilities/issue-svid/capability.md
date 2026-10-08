---
availability:
  - place: "server-api::agents"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/svid/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/manager.go
---

# Issue an SVID

An agent has the server sign X.509-SVIDs or a JWT-SVID for registration
entries it is authorized for. The identity, DNS names and lifetime come from
the entry.
