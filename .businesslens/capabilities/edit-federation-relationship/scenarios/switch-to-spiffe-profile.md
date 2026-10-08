---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator names the trust domain of an https_web relationship and supplies the https_spiffe profile with the endpoint SPIFFE ID
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product replaces the https_web relationship with an https_spiffe one for the same trust domain
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: removes}
      - {entity: spiffe-federation-relationship, effect: creates, facts: [Trust domain, Bundle endpoint URL, Endpoint SPIFFE ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Switch a relationship to the https_spiffe profile

## Trigger

A foreign trust domain moves its bundle endpoint from Web PKI to SPIFFE
authentication.

## Outcome

The server authenticates the endpoint with SPIFFE authentication from its next
refresh.

## Edge cases

- Switching back to https_web works the same way.
