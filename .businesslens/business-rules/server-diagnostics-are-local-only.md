---
appliesTo:
  - type: capability
    id: check-health
    contexts:
      - place: server-cli
      - place: "server-api::administration"
  - type: capability
    id: get-debug-info
    contexts:
      - place: server-cli
      - place: "server-api::administration"
  - type: capability
    id: get-logger
    contexts:
      - place: server-cli
      - place: "server-api::administration"
  - type: capability
    id: set-log-level
    contexts:
      - place: server-cli
      - place: "server-api::administration"
  - type: capability
    id: reset-log-level
    contexts:
      - place: server-cli
      - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# The server's health, debug information and logging level are open only to local callers

Admin workloads are refused these calls; only callers on the server's local
socket are served.
