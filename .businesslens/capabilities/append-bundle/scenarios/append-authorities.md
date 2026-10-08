---
kind: primary
routes:
  api: Server API
steps:
  - text: The Admin workload sends X.509 CA certificates or JWT public keys to add
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: "The Product adds them to the server's own bundle"
    kind: product
    actor: admin-workload
    entities:
      - {entity: bundle, effect: changes, facts: [X.509 authorities, JWT authorities, Sequence number]}
    contexts:
      api: { place: "server-api::administration" }
---

# Append authorities to the bundle

## Trigger

Software that administers SPIRE needs additional authorities trusted inside
the trust domain.

## Outcome

The server's bundle carries the added authorities, and agents deliver them at
their next sync.

## Edge cases

- A request with no authorities is refused with "no authorities to append".
- Malformed certificates or keys are refused.
