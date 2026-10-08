---
appliesTo:
  - type: entity
    id: agent
    effect: removes
permits:
  - actors:
      - operator
      - admin-workload
  - unattended: true
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: code
    role: implementation
    target: pkg/server/node/manager.go
---

# Only operators, admin workloads and expiry pruning remove agents

An agent is evicted or purged by a caller on the local socket or an admin
workload, or pruned by the server when it is configured to prune expired
agents.
