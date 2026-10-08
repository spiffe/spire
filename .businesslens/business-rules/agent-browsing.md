---
appliesTo:
  - type: entity
    id: agent
    effect: reads
    contexts:
      - place: server-cli
      - place: "server-api::administration"
permits:
  - actors:
      - operator
      - admin-workload
  - unattended: true
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads list, show and count agents

The server's agent records are open to callers on the local socket and admin
workloads only; the server reads them itself to prune expired agents.
