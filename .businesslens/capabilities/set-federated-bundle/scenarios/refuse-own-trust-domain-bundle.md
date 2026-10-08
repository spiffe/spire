---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the server's own trust domain with CA data"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product refuses because the trust domain is its own
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Setting the server's own bundle is refused

## Trigger

An Operator names the server's own trust domain.

## Outcome

Nothing changes; "setting a federated bundle for the server's own trust domain
is not allowed".
