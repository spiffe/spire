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
  - text: The Product returns the number of matching registration entries
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: reads, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Count registration entries

## Trigger

An Operator wants to know how many registration entries match.

## Outcome

The Operator sees the number of matching entries.
