---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the prepared JWT authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: jwt-authority, as: next, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product activates the prepared authority and makes the active one old
    kind: product
    actor: operator
    entities:
      - {entity: jwt-authority, as: next, effect: changes, from: Prepared, to: Active, facts: []}
      - {entity: jwt-authority, as: current, effect: changes, from: Active, to: Old, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Activate a JWT authority

## Trigger

An Operator has let a prepared JWT authority propagate and switches to it.

## Outcome

The prepared authority signs everything new; the previous one is old and still
trusted.

## Edge cases

- An ID that is not the prepared authority's is refused with "unexpected authority ID".
