---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator asks for the debug information of the SPIRE process on the node
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: "The Product returns its uptime, its own SVID chain, the number of SVIDs it caches and when it last synced"
    kind: product
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
---

# Get the agent's debug information

## Trigger

An Operator diagnoses a SPIRE Agent.

## Outcome

The Operator sees the agent's state at a glance.

## Edge cases

- The command needs the Agent Admin API socket to be configured.
