---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for the state of the X.509 signing authorities
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns the active, prepared and old X.509 authorities"
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID, Expires at, Upstream authority subject key ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Show X.509 authorities

## Trigger

An Operator plans an X.509 authority rotation.

## Outcome

The Operator sees the active, prepared and old authorities with their IDs and
expiry, or that one of them does not exist.

## Edge cases

- While the server is still initializing, the request is refused.
