---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Downstream server asks its upstream server for its trust material
    kind: actor
    actor: downstream-server
    entities: []
    contexts:
      api: { place: "server-api::downstream" }
  - text: The Product returns its own bundle
    kind: product
    actor: downstream-server
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::downstream" }
---

# A downstream server fetches the bundle

## Trigger

A downstream server keeps its own bundle in step with its upstream server.

## Outcome

The downstream server holds the upstream bundle, including JWT authorities
other downstream servers published.
