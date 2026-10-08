---
kind: primary
routes:
  api: Server API
steps:
  - text: The Downstream server sends a certificate signing request with a preferred lifetime
    kind: actor
    actor: downstream-server
    entities: []
    contexts:
      api: { place: "server-api::downstream" }
  - text: "The Product signs the downstream CA with the active X.509 authority and returns it with the bundle's X.509 authorities"
    kind: product
    actor: downstream-server
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID, Expires at]}
      - {entity: bundle, effect: reads, facts: [X.509 authorities]}
    contexts:
      api: { place: "server-api::downstream" }
---

# Sign a downstream X.509 CA

## Trigger

A downstream server prepares a new X.509 authority.

## Outcome

The downstream server holds a CA certificate that expires no later than this
server's own CA, and the X.509 authorities of the bundle.

## Edge cases

- A caller without a Downstream registration entry is refused with "caller is not a downstream workload".
- With the legacy downstream CA lifetime setting, the lifetime comes from the downstream entry's X509-SVID TTL instead of the request.
