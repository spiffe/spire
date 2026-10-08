---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for a new X.509 signing authority
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product generates an X.509 authority and adds its CA certificate to the bundle
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, effect: creates, to: Prepared, facts: [Authority ID, Expires at, Upstream authority subject key ID]}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Prepare an X.509 authority

## Trigger

An Operator rotates the X.509 authority ahead of schedule.

## Outcome

A new prepared authority is in the bundle; it takes the place of any old
authority in the next slot.

## Edge cases

- While the server is still initializing, the request is refused.
