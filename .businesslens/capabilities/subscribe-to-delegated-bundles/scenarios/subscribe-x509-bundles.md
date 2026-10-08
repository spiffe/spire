---
kind: primary
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate subscribes to X.509 trust material
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: "The Product sends the X.509 authorities of every bundle it holds, then each change"
    kind: product
    actor: authorized-delegate
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      del: { place: delegated-identity-api }
---

# Subscribe to X.509 bundles

## Trigger

An authorized delegate verifies peers on behalf of other processes.

## Outcome

The delegate holds every X.509 bundle the agent knows and receives each
change.
