---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator asks whether the SPIRE process on the node is healthy
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: The Product fetches identities through its own public endpoint and answers serving unless that fails for a reason other than having no identity
    kind: product
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
---

# Check the agent's health

## Trigger

An Operator or a script checks a SPIRE Agent.

## Outcome

The Operator learns whether the agent is healthy.

## Edge cases

- With the Workload API disabled the agent always answers serving; the HTTP health checks are used instead.
