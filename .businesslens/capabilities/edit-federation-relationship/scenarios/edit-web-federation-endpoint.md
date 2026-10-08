---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain and supplies the new endpoint URL
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product changes the federation relationship
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: changes, facts: [Bundle endpoint URL]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Edit an https_web relationship's endpoint

## Trigger

A foreign trust domain moved its Web PKI bundle endpoint.

## Outcome

The relationship carries the new URL and the server fetches from it.
