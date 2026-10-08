---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names a trust domain without a federation relationship
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product refuses because no relationship covers that trust domain
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: reads, facts: [Trust domain]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Refreshing a trust domain without a relationship is refused

## Trigger

An Operator names a trust domain the server does not federate with.

## Outcome

Nothing is fetched; the Product reports there is no relationship with the
trust domain.
