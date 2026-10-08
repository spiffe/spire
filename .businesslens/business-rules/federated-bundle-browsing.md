---
appliesTo:
  - type: entity
    id: bundle
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

# Only operators and admin workloads list and count bundles at the administration places

Listing federated bundles and counting bundles are open to callers on the
local socket and admin workloads; the server's own bundle is open to anyone
through the Server API and the bundle endpoint, and an attested agent fetches
the federated bundles its entries need.
