---
appliesTo:
  - type: entity
    id: jwt-svid
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

# Only attested agents have JWT-SVIDs signed for their entries

At the agent places, JWT-SVIDs are signed only for an attested agent and only
for entries it is authorized for.
