---
kind: validation
routes:
  api: Server API
steps:
  - text: The Agent presents its evidence
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: "The Agent's record is banned"
    kind: condition
    actor: agent
    entities:
      - {entity: agent, effect: reads, facts: []}
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: "The Product refuses with \"agent is banned\""
    kind: product
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
---

# A banned agent cannot attest

## Trigger

An agent an Operator banned tries to attest again.

## Outcome

The agent is refused with "agent is banned", and it deletes its SVID and shuts
down.
