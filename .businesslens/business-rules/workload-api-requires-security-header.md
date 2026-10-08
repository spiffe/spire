---
appliesTo:
  - type: context
    context:
      place: workload-api
  - type: context
    context:
      place: agent-cli
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/middleware.go
---

# Every Workload API request carries the security header

The agent refuses Workload API requests without the `workload.spiffe.io`
header, which shows the request did not come through a proxy forwarding
untrusted input.
