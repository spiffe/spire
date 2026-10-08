---
kind: primary
routes:
  api: Server API
steps:
  - text: The Admin workload sends the trust material of a foreign trust domain
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: The Product creates the federated bundle
    kind: product
    actor: admin-workload
    entities:
      - {entity: bundle, effect: creates, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::administration" }
---

# Create a federated bundle

## Trigger

Software that administers SPIRE obtained a foreign trust domain's bundle out
of band.

## Outcome

The server holds that bundle; entries federating with the trust domain deliver
it to their workloads.

## Edge cases

- The server's own trust domain is refused.
