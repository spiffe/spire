---
kind: alternative
routes:
  brk: SPIFFE Broker API
steps:
  - text: The Broker sends a reference and subscribes to JWT trust material
    kind: actor
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
  - text: "The Product attests the reference and sends the JWT authorities of every bundle it holds, then each change"
    kind: product
    actor: broker
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, JWT authorities]}
    contexts:
      brk: { place: broker-api }
---

# Subscribe to JWT bundles as a broker

## Trigger

A broker verifies JWT-SVIDs on behalf of a workload.

## Outcome

The broker holds every JWT bundle the agent knows and receives each change.
