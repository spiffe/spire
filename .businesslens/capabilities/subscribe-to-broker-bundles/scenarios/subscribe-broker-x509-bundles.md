---
kind: primary
routes:
  brk: SPIFFE Broker API
steps:
  - text: The Broker sends a reference and subscribes to X.509 trust material
    kind: actor
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
  - text: "The Product attests the reference and sends the X.509 authorities of every bundle it holds, then each change"
    kind: product
    actor: broker
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      brk: { place: broker-api }
---

# Subscribe to X.509 bundles as a broker

## Trigger

A broker verifies peers on behalf of a workload.

## Outcome

The broker holds every X.509 bundle the agent knows, including the removal of
trust domains it no longer holds.
