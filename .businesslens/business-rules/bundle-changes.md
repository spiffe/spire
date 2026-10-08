---
appliesTo:
  - type: entity
    id: bundle
    effect: changes
permits:
  - actors:
      - operator
      - admin-workload
  - actors:
      - downstream-server
  - unattended: true
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators, admin workloads, downstream servers and the server itself change bundles

A bundle changes when a caller on the local socket or an admin workload sets,
edits or appends to it, manages authorities or refreshes it, when a downstream
server publishes a JWT authority, or when the server rotates its authorities
and refreshes federated bundles on its own.
