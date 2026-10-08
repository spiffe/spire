---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain of an https_spiffe relationship
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the federation relationship
    kind: product
    actor: operator
    entities:
      - {entity: spiffe-federation-relationship, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete an https_spiffe relationship

## Trigger

An Operator stops federating with a foreign SPIRE Server.

## Outcome

The relationship is gone; the bundle stays until it is deleted.
