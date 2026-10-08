---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The active X.509 authority reaches its activation threshold
    kind: condition
    unattended: true
    entities:
      - {entity: x509-authority, as: current, effect: reads, facts: [Expires at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product activates the prepared authority and makes the active one old
    kind: product
    entities:
      - {entity: x509-authority, as: next, effect: changes, from: Prepared, to: Active, facts: []}
      - {entity: x509-authority, as: current, effect: changes, from: Active, to: Old, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# The prepared X.509 authority is activated on schedule

## Trigger

The active authority has less than a sixth of its lifetime, or seven days,
left.

## Outcome

The prepared authority signs everything new; the previous one is old and still
trusted.

## Edge cases

- An X.509 authority is activated only if it expires later than the active one; otherwise the server prepares again.
