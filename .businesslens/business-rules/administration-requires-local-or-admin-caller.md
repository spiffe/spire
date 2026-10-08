---
appliesTo:
  - type: context
    context:
      place: "server-api::administration"
  - type: context
    context:
      place: server-cli
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: code
    role: implementation
    target: pkg/server/api/middleware/authorization.go
---

# Administration requires a local caller or an admin workload

Administration calls are accepted from callers on the server's local socket
and from callers whose SPIFFE ID is in `admin_ids` or carried by an entry
marked Admin; everyone else is refused as unauthorized.
