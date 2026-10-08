---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator chooses optional filters
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product returns the number of matching agents
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Count attested agents

## Trigger

An Operator wants to know how many agents match.

## Outcome

The Operator sees the number of matching agents.
