---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator resets the logging level of the SPIRE process on the node
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: The Product applies it to the Logger and returns the current and launch levels
    kind: product
    actor: operator
    entities:
      - {entity: logger, effect: changes, facts: [Current level]}
    contexts:
      cli: { place: agent-cli }
---

# Reset the log level of the agent

## Trigger

An Operator diagnoses a running SPIRE Agent through its Agent Admin API
socket.

## Outcome

The component logs at its launch level again.
