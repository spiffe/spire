---
appliesTo:
  - type: entity
    id: web-federation-relationship
    effect: changes
  - type: entity
    id: spiffe-federation-relationship
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

# Only operators and admin workloads change federation relationships

Dynamic federation relationships are managed only by a caller on the local
socket or an admin workload.
