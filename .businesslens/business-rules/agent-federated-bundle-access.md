---
appliesTo:
  - type: entity
    id: bundle
    effect: reads
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

# Only attested agents fetch bundles at the agent places

An attested agent fetches the server's bundle and any federated bundle by
trust domain.
