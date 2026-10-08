---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for the state of the JWT signing keys
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns the active, prepared and old JWT authorities"
    kind: product
    actor: operator
    entities:
      - {entity: jwt-authority, effect: reads, facts: [Authority ID, Expires at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Show JWT authorities

## Trigger

An Operator plans a JWT authority rotation.

## Outcome

The Operator sees the active, prepared and old authorities with their IDs and
expiry, or that one of them does not exist.

## Edge cases

- While the server has JWT-SVIDs disabled the request is refused as "JWT functionality is disabled".
