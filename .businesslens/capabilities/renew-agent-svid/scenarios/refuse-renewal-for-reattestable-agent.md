---
kind: validation
routes:
  api: Server API
steps:
  - text: The Agent asks for a new SVID
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Agent can re-attest
    kind: condition
    actor: agent
    entities:
      - {entity: agent, effect: reads, facts: [Can re-attest]}
    contexts:
      api: { place: "server-api::agents" }
  - text: "The Product refuses with \"agent must reattest instead of renew\""
    kind: product
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
---

# A re-attestable agent must re-attest

## Trigger

An agent that can re-attest asks to renew.

## Outcome

The agent is told it must re-attest instead of renew, and does.
