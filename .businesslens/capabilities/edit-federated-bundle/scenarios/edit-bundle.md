---
kind: primary
routes:
  api: Server API
steps:
  - text: The Admin workload names a trust domain and sends the values to change
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: The Product changes those values of the federated bundle
    kind: product
    actor: admin-workload
    entities:
      - {entity: bundle, effect: changes, facts: [X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::administration" }
---

# Edit a federated bundle

## Trigger

Software that administers SPIRE updates part of a foreign trust domain's
bundle.

## Outcome

The federated bundle carries the new values and keeps the others.

## Edge cases

- A trust domain the server holds no bundle for is refused with "bundle not found".
- The server's own trust domain is refused.
