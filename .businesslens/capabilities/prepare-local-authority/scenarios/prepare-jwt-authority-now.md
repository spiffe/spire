---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for a new JWT signing key
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product generates a JWT authority and adds its public key to the bundle
    kind: product
    actor: operator
    entities:
      - {entity: jwt-authority, effect: creates, to: Prepared, facts: [Authority ID, Expires at]}
      - {entity: bundle, effect: changes, facts: [JWT authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Prepare a JWT authority

## Trigger

An Operator rotates the JWT authority ahead of schedule.

## Outcome

A new prepared authority is in the bundle; it takes the place of any old
authority in the next slot.
