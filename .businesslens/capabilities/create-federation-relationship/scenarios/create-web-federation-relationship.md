---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator supplies the trust domain, the HTTPS endpoint URL and the https_web profile"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates the federation relationship and starts refreshing the foreign trust material
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: creates, facts: [Trust domain, Bundle endpoint URL]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Federate through an https_web bundle endpoint

## Trigger

An Operator wants workloads to trust identities from a foreign trust domain
whose endpoint has a Web PKI certificate.

## Outcome

The relationship exists and the server begins fetching the foreign bundle from
its endpoint.

## Edge cases

- A URL that is not HTTPS, has no host or carries user info is refused.
- A relationship with the server's own trust domain is refused.
