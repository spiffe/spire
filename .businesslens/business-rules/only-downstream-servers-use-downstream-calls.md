---
appliesTo:
  - type: context
    context:
      place: "server-api::downstream"
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only downstream servers obtain a downstream CA or publish JWT authorities

Signing a downstream X.509 CA and publishing a JWT authority are open only to
callers whose SPIFFE ID a registration entry marks Downstream.
