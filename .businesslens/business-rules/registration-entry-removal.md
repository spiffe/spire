---
appliesTo:
  - type: entity
    id: registration-entry
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
    target: pkg/server/registration/manager.go
---

# Only operators, admin workloads and expiry remove registration entries

A registration entry is removed by a caller on the local socket or an admin
workload, or by the server once its expiry has passed.
