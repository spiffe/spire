---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the old JWT authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: jwt-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product marks the old authority tainted in the bundle
    kind: product
    actor: operator
    entities:
      - {entity: jwt-authority, effect: changes, from: Old, to: Tainted, facts: []}
      - {entity: bundle, effect: changes, facts: [JWT authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Taint the old JWT authority

## Trigger

An Operator suspects the old JWT authority's key is compromised, after
activating a replacement.

## Outcome

The authority is tainted; agents learn of it at their next sync and replace
every JWT-SVID it signed.

## Edge cases

- The active authority cannot be tainted, and only the old one can.
- An authority already tainted is refused.
