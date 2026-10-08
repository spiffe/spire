---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator asks for the server's logging level"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product applies it to the Logger and returns the current and launch levels
    kind: product
    actor: operator
    entities:
      - {entity: logger, effect: reads, facts: [Current level, Launch level]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Get the logger of the server

## Trigger

An Operator diagnoses a running SPIRE Server.

## Outcome

The Operator sees the current and launch levels.
