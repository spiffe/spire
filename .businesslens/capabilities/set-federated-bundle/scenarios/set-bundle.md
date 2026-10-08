---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain and supplies its CA certificates and keys in PEM or SPIFFE format
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates the bundle for that trust domain
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: creates, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Set a new federated bundle

## Trigger

An Operator obtained a foreign trust domain's bundle out of band.

## Outcome

The server holds that bundle; entries federating with the trust domain deliver
it to their workloads.
