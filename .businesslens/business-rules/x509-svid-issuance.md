---
appliesTo:
  - type: entity
    id: x509-svid
    effect: creates
    contexts:
      - place: "server-api::agents"
permits:
  - actors:
      - agent
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only attested agents have X.509-SVIDs signed for their entries

At the agent places, X.509-SVIDs are signed only for an attested agent and
only for entries it is authorized for.
