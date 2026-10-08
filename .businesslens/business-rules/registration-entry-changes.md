---
appliesTo:
  - type: entity
    id: registration-entry
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

# Only operators and admin workloads change registration entries

A registration entry is changed only by a caller on the local socket or an
admin workload.
