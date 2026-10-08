---
appliesTo:
  - type: entity
    id: upstream-authority
    effect: changes
permits:
  - actors:
      - operator
      - admin-workload
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads taint upstream authorities

An upstream authority is tainted only by a caller on the local socket or an
admin workload, and only one that signed the old X.509 authority.
