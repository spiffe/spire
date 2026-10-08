---
appliesTo:
  - type: entity
    id: jwt-svid
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

# Only operators and admin workloads mint JWT-SVIDs

Minting a JWT-SVID without a registration entry is open only to callers on the
local socket and admin workloads.
