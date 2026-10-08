---
appliesTo:
  - type: entity
    id: registration-entry
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

# Only operators and admin workloads create registration entries

Registration entries are created only by a caller on the server's local
socket, such as the Operator's command line, or by an admin workload.
