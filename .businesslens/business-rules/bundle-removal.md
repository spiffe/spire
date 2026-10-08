---
appliesTo:
  - type: entity
    id: bundle
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

# Only operators and admin workloads delete federated bundles

A federated bundle is removed only by a caller on the local socket or an admin
workload.
