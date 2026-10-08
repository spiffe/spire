---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain
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
      - {entity: web-federation-relationship, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete a federation relationship

## Trigger

An Operator no longer wants the server to keep a foreign bundle current.

## Outcome

The relationship is gone; the server stops refreshing the bundle, which it
still holds.

## Edge cases

- An unknown trust domain is refused as not found.
- A static relationship from the configuration file for the same trust domain keeps applying.
