---
appliesTo:
  - type: entity
    id: registration-entry
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

# Only operators and admin workloads browse registration entries

Listing, showing and counting registration entries is open to callers on the
local socket and admin workloads only; the server reads them itself to prune
expired entries.
