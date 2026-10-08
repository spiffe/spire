---
kind: alternative
routes:
  bep: SPIFFE bundle endpoint
steps:
  - text: "The Federated server requests the trust domain's trust material over HTTPS"
    kind: actor
    actor: federated-server
    entities: []
    contexts:
      bep: { place: bundle-endpoint }
  - text: "The Product returns its own trust domain's bundle with its configured refresh hint"
    kind: product
    actor: federated-server
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      bep: { place: bundle-endpoint }
---

# Serve the bundle to a federated trust domain

## Trigger

A federated server polls this trust domain's bundle endpoint.

## Outcome

The caller holds this trust domain's current bundle with the refresh hint the
server is configured with, five minutes by default.

## Edge cases

- Only GET on the root path is served; other methods are refused and other paths are not found.
