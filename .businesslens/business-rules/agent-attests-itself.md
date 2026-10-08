---
appliesTo:
  - type: entity
    id: agent
    effect: creates
permits:
  - self: true
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/agent/v1/service.go#AttestAgent"
---

# An agent is recorded only by attesting itself

Anyone may start node attestation, but an agent record is created only for the
node whose evidence the configured node attestor verified.
