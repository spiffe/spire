---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator optionally names a trust domain
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns the dynamic federation relationships, or the one asked for"
    kind: product
    actor: operator
    entities:
      - {entity: web-federation-relationship, effect: reads, facts: [Trust domain, Bundle endpoint URL]}
      - {entity: spiffe-federation-relationship, effect: reads, facts: [Trust domain, Bundle endpoint URL, Endpoint SPIFFE ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# List federation relationships

## Trigger

An Operator wants to see which trust domains the server federates with.

## Outcome

The Operator sees each relationship with its endpoint and profile.

## Edge cases

- An unknown trust domain is refused as not found.
