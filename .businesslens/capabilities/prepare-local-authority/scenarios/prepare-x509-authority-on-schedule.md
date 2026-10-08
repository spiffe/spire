---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The active X.509 authority reaches its preparation threshold
    kind: condition
    unattended: true
    entities:
      - {entity: x509-authority, effect: reads, facts: [Expires at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product generates the next X.509 authority and adds it to the bundle
    kind: product
    entities:
      - {entity: x509-authority, effect: creates, to: Prepared, facts: [Authority ID, Expires at, Upstream authority subject key ID]}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# The next X.509 authority is prepared on schedule

## Trigger

The active authority has less than half of its lifetime, or 30 days, left.

## Outcome

A prepared authority is in the bundle ahead of activation.

## Edge cases

- A failed preparation is retried on a later check.
