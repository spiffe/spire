---
type: api
actors:
  - operator
  - admin-workload
  - agent
  - downstream-server
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: code
    role: implementation
    target: pkg/server/api/middleware/caller.go
  - kind: code
    role: implementation
    target: pkg/server/endpoints/endpoints.go
  - kind: spec
    role: context
    target: "https://github.com/spiffe/spire-api-sdk"
    title: SPIRE API SDK
---

# SPIRE Server API

The gRPC API of the SPIRE Server, served over TCP with mutual TLS and on a
local socket. Who may call each method depends on the caller: anyone, a caller
on the local socket, an admin, an attested agent, or a downstream server.
