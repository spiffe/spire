---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator names the configuration file of the SPIRE process on the node
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: The Product loads it and reports whether it is valid
    kind: product
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
---

# Validate the agent configuration

## Trigger

An Operator changed an agent configuration.

## Outcome

The Operator sees that the configuration is valid, or the errors in it.
