---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the old X.509 authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product marks the old authority tainted in the bundle
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, effect: changes, from: Old, to: Tainted, facts: []}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Taint the old X.509 authority

## Trigger

An Operator suspects the old X.509 authority's key is compromised, after
activating a replacement.

## Outcome

The authority is tainted; agents learn of it at their next sync and replace
every SVID it signed.

## Edge cases

- The active authority cannot be tainted, and only the old one can.
- An authority already tainted is refused.
