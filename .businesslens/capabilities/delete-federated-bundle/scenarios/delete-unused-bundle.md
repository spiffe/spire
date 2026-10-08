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
  - text: The Product removes the bundle
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete a federated bundle

## Trigger

An Operator stops trusting a foreign trust domain no entry federates with.

## Outcome

The bundle is gone.

## Edge cases

- The server's own bundle is never removed: "removing the bundle for the server trust domain is not allowed".
