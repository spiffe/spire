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
    target: cmd/spire-agent/cli/api/fetch_x509.go
  - kind: code
    role: implementation
    target: cmd/spire-agent/cli/api/fetch_jwt.go
  - kind: code
    role: implementation
    target: cmd/spire-agent/cli/api/watch.go
---

# Fetch SVIDs

A workload receives an X.509-SVID with its private key for every registration
entry it matches, with its trust domain's bundle and the federated bundles its
entries federate with, and keeps receiving replacements as they rotate; or it
receives a JWT-SVID for the audiences it names, for each of its identities or
for one SPIFFE ID it asks for.
