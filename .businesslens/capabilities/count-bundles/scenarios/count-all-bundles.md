---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for the count
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product returns the number of bundles
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Count bundles

## Trigger

An Operator wants to know how many bundles the server holds.

## Outcome

The Operator sees the number of bundles, the server's own included.
