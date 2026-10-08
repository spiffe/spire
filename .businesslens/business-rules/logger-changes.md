---
appliesTo:
  - type: entity
    id: logger
    effect: changes
permits:
  - actors:
      - operator
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: code
    role: implementation
    target: pkg/agent/api/endpoints.go
---

# Only operators change a component's logging level

Server logger calls are open only to callers on the server's local socket;
agent logger calls are served only on the Agent Admin API socket.
