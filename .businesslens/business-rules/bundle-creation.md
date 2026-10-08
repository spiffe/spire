---
appliesTo:
  - type: entity
    id: bundle
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

# Only operators and admin workloads create federated bundles

A federated bundle is created only by a caller on the local socket or an admin
workload, directly or with a federation relationship.
