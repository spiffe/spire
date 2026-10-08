---
appliesTo:
  - type: capability
    id: validate-jwt-svid
    contexts:
      - place: workload-api
      - place: agent-cli
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
---

# Validation returns only standard claims from foreign JWT-SVIDs

When a JWT-SVID from a federated trust domain is validated, only its subject,
expiry and audience claims and those the agent's `allowed_foreign_jwt_claims`
setting lists are returned.
