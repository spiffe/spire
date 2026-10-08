---
domain: workload-api
availability:
  - place: workload-api
  - place: agent-cli
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/manager.go
  - kind: code
    role: implementation
    target: cmd/spire-agent/cli/api/validate_jwt.go
---

# Validate a JWT-SVID

Check a JWT-SVID presented by someone else against the bundles the caller
trusts and an expected audience, and get its SPIFFE ID and claims.
