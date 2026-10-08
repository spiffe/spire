---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The time to poll a federated trust domain's bundle endpoint has come"
    kind: condition
    unattended: true
    entities:
      - {entity: web-federation-relationship, effect: reads, facts: [Trust domain, Bundle endpoint URL]}
      - {entity: spiffe-federation-relationship, effect: reads, facts: [Trust domain, Bundle endpoint URL, Endpoint SPIFFE ID]}
      - {entity: bundle, effect: reads, facts: [Refresh hint]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product fetches the bundle, authenticating the endpoint by its profile, and stores it when it differs from the one held"
    kind: product
    entities:
      - {entity: bundle, effect: changes, facts: [X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Federated bundles are refreshed periodically

## Trigger

For every trust domain under a federation relationship, static or dynamic, the
server polls the bundle endpoint: a quarter of the refresh hint after the last
poll, every five minutes without a hint, and every minute while it holds no
bundle.

## Outcome

Each federated bundle tracks what its endpoint serves without anyone asking.

## Edge cases

- Under https_spiffe with no bundle held and no bootstrap bundle configured, the endpoint cannot be authenticated and nothing is stored.
