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
  - text: The Product fetches the bundle from the endpoint and stores it when it differs
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: reads, facts: [Trust domain, Bundle endpoint URL]}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Refresh a federated bundle now

## Trigger

An Operator knows a foreign trust domain rotated its authorities.

## Outcome

The server holds the bundle its endpoint serves now.

## Edge cases

- A failed fetch is reported and the held bundle is kept.
