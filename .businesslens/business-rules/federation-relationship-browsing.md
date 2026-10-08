---
appliesTo:
  - type: entity
    id: web-federation-relationship
    effect: reads
    contexts:
      - place: server-cli
      - place: "server-api::administration"
  - type: entity
    id: spiffe-federation-relationship
    effect: reads
    contexts:
      - place: server-cli
      - place: "server-api::administration"
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

# Only operators, admin workloads and the refresh schedule read federation relationships

Dynamic federation relationships are listed only to callers on the local
socket and admin workloads; the server reads them itself to refresh federated
bundles.
