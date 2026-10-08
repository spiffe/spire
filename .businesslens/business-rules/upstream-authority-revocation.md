---
appliesTo:
  - type: entity
    id: upstream-authority
    effect: removes
permits:
  - actors:
      - operator
      - admin-workload
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads revoke upstream authorities

A tainted upstream authority is removed from the bundle only by a caller on
the local socket or an admin workload.
