---
appliesTo:
  - type: entity
    id: x509-authority
    effect: creates
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
    target: pkg/server/ca/rotator/rotator.go
---

# Only operators, admin workloads and the rotation schedule prepare X.509 authorities

An X.509 authority is prepared by a caller on the local socket or an admin
workload, or by the server's own rotation.
