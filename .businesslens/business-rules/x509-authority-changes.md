---
appliesTo:
  - type: entity
    id: x509-authority
    effect: changes
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

# Only operators, admin workloads and the rotation schedule activate or taint X.509 authorities

An X.509 authority is activated or tainted by a caller on the local socket or
an admin workload; the server's rotation also activates on its own.
