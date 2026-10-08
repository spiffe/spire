---
appliesTo:
  - type: entity
    id: join-token
    effect: creates
permits:
  - actors:
      - operator
      - admin-workload
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads generate join tokens

Join tokens are created only by a caller on the local socket or an admin
workload.
