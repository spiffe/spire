---
appliesTo:
  - type: entity
    id: agent
    effect: changes
    to: Banned
permits:
  - actors:
      - operator
      - admin-workload
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads ban agents

An agent is banned only by a caller on the local socket or an admin workload.
