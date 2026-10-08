---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator chooses a new logging level for the server
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
      - {entity: logger, effect: changes, facts: [Current level]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Set the log level of the server

## Trigger

An Operator diagnoses a running SPIRE Server.

## Outcome

The component logs at the new level until it is reset or restarted.

## Edge cases

- A missing or unsupported level is refused.
