---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator supplies the trust domain, the endpoint URL, its SPIFFE ID and the foreign trust domain's current trust material"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates the federation relationship and stores the bundle it was given
    kind: product
    actor: operator
    entities:
      - {entity: spiffe-federation-relationship, effect: creates, facts: [Trust domain, Bundle endpoint URL, Endpoint SPIFFE ID]}
      - {entity: bundle, effect: creates, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Federate through an https_spiffe bundle endpoint

## Trigger

An Operator federates with a foreign SPIRE Server whose endpoint authenticates
with its own X.509-SVID.

## Outcome

The relationship exists and the foreign bundle is stored, so the server can
authenticate the endpoint at its first refresh.

## Edge cases

- The https_spiffe profile requires the endpoint SPIFFE ID.
- A bundle of another trust domain than the relationship's is refused.
- A bundle given for a trust domain the server already holds replaces it.
