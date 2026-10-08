---
appliesTo:
  - type: entity
    id: x509-svid
    effect: creates
    contexts:
      - place: server-cli
      - place: "server-api::administration"
permits:
  - actors:
      - operator
      - admin-workload
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only operators and admin workloads mint X.509-SVIDs

Minting an X.509-SVID without a registration entry is open only to callers on
the local socket and admin workloads.
