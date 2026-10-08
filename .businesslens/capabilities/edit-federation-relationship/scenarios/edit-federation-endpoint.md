---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain and supplies the new endpoint URL and endpoint SPIFFE ID
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
      - {entity: spiffe-federation-relationship, effect: changes, facts: [Bundle endpoint URL, Endpoint SPIFFE ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Edit a federation relationship's endpoint

## Trigger

A foreign trust domain moved its bundle endpoint.

## Outcome

The relationship carries the new values and the server fetches from the new
endpoint.

## Edge cases

- A bundle given with the change replaces the one the server holds for that trust domain.
