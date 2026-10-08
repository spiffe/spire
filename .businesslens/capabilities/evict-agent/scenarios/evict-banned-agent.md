---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the banned agent's SPIFFE ID"
    kind: actor
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the agent and its node selectors
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: removes, from: Banned}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Evict a banned agent

## Trigger

An Operator lifts a ban on a node that has been cleaned up.

## Outcome

The ban is gone with the record; the node can attest again with fresh
evidence.
