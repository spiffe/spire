---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain in delete mode
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product removes every registration entry federating with the bundle, then the bundle"
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: removes}
      - {entity: bundle, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete a bundle with its entries

## Trigger

An Operator deletes a bundle in delete mode.

## Outcome

The bundle and every registration entry that federated with it are gone.
