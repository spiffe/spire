---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator asks for the logging level of the SPIRE process on the node
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: The Product applies it to the Logger and returns the current and launch levels
    kind: product
    actor: operator
    entities:
      - {entity: logger, effect: reads, facts: [Current level, Launch level]}
    contexts:
      cli: { place: agent-cli }
---

# Get the logger of the agent

## Trigger

An Operator diagnoses a running SPIRE Agent through its Agent Admin API
socket.

## Outcome

The Operator sees the current and launch levels.
