---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain in dissociate mode
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product removes the trust domain from every registration entry federating with it, then removes the bundle"
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: changes, facts: [Federates with]}
      - {entity: bundle, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete a bundle and dissociate its entries

## Trigger

An Operator deletes a bundle in dissociate mode.

## Outcome

The bundle is gone and the entries that federated with it no longer do.
