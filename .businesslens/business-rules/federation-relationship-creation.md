---
appliesTo:
  - type: entity
    id: web-federation-relationship
    effect: creates
  - type: entity
    id: spiffe-federation-relationship
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

# Only operators and admin workloads create federation relationships

Dynamic federation relationships are managed only by a caller on the local
socket or an admin workload.
