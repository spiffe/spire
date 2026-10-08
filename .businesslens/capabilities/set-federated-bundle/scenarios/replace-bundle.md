---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names a foreign trust domain the server already trusts and supplies new data
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product replaces the bundle
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: changes, facts: [X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Replace a federated bundle

## Trigger

A foreign trust domain rotated its authorities and the Operator received the
new bundle.

## Outcome

The server holds the new bundle in place of the old one.
