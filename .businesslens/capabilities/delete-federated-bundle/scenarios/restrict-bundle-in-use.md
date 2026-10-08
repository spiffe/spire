---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the trust domain in restrict mode, the default"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product refuses because registration entries federate with the bundle
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain]}
      - {entity: registration-entry, effect: reads, facts: [Federates with]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Deleting a bundle entries federate with is refused

## Trigger

An Operator deletes, in restrict mode, a bundle that registration entries
federate with.

## Outcome

Nothing changes; the Product reports that entries federate with the bundle.
