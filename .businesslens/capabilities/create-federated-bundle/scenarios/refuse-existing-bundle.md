---
kind: validation
routes:
  api: Server API
steps:
  - text: The Admin workload sends trust material for a trust domain the server already holds
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: "The Product refuses with \"bundle already exists\""
    kind: product
    actor: admin-workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain]}
    contexts:
      api: { place: "server-api::administration" }
---

# Creating a bundle that exists is refused

## Trigger

A bundle for the trust domain is already held.

## Outcome

Nothing changes; the held bundle is kept.
