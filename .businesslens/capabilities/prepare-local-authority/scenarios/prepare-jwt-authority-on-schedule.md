---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The active JWT authority reaches its preparation threshold
    kind: condition
    unattended: true
    entities:
      - {entity: jwt-authority, effect: reads, facts: [Expires at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product generates the next JWT authority and adds it to the bundle
    kind: product
    entities:
      - {entity: jwt-authority, effect: creates, to: Prepared, facts: [Authority ID, Expires at]}
      - {entity: bundle, effect: changes, facts: [JWT authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# The next JWT authority is prepared on schedule

## Trigger

The active authority has less than half of its lifetime, or 30 days, left.

## Outcome

A prepared authority is in the bundle ahead of activation.
