---
kind: alternative
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate subscribes to JWT trust material
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: "The Product sends the JWT authorities of every bundle it holds, then each change"
    kind: product
    actor: authorized-delegate
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, JWT authorities]}
    contexts:
      del: { place: delegated-identity-api }
---

# Subscribe to JWT bundles

## Trigger

An authorized delegate verifies JWT-SVIDs on behalf of other processes.

## Outcome

The delegate holds every JWT bundle the agent knows and receives each change.
