---
type: api
actors:
  - workload
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/middleware.go
  - kind: spec
    role: intent
    target: "https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md"
    title: SPIFFE Workload API
---

# SPIFFE Workload API

The SPIFFE Workload API the agent serves on a local socket or named pipe.
Callers do not authenticate: the agent identifies each one by attesting the
calling process into selectors, and every request must carry the Workload API
security header.
