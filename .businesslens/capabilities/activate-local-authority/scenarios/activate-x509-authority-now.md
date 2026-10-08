---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the prepared X.509 authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: x509-authority, as: next, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product activates the prepared authority and makes the active one old
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, as: next, effect: changes, from: Prepared, to: Active, facts: []}
      - {entity: x509-authority, as: current, effect: changes, from: Active, to: Old, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Activate an X.509 authority

## Trigger

An Operator has let a prepared X.509 authority propagate and switches to it.

## Outcome

The prepared authority signs everything new; the previous one is old and still
trusted.

## Edge cases

- An ID that is not the prepared authority's is refused with "unexpected authority ID".
- Only a prepared authority can be activated.
- A prepared X.509 authority that has already expired is refused.
