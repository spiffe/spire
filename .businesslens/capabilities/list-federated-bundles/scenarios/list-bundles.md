---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator optionally names a trust domain and a format
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns the federated bundles, or the one asked for"
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# List federated bundles

## Trigger

An Operator wants to see which foreign trust domains are trusted.

## Outcome

The Operator sees each federated bundle, or the one asked for.

## Edge cases

- Asking for the server's own trust domain as a federated bundle is refused.
