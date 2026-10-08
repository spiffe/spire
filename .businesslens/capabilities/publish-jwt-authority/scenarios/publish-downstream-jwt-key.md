---
kind: primary
routes:
  api: Server API
steps:
  - text: The Downstream server sends its JWT signing public key and its expiry
    kind: actor
    actor: downstream-server
    entities: []
    contexts:
      api: { place: "server-api::downstream" }
  - text: "The Product adds the key to the bundle, or forwards it to its own upstream server when it is itself downstream"
    kind: product
    actor: downstream-server
    entities:
      - {entity: bundle, effect: changes, facts: [JWT authorities, Sequence number]}
    contexts:
      api: { place: "server-api::downstream" }
---

# Publish a downstream JWT authority

## Trigger

A downstream server prepares a new JWT authority.

## Outcome

The key is in the top server's bundle, and the downstream server receives
every JWT authority published so far.

## Edge cases

- Publishing too often is refused by rate limiting.
- A missing or malformed key is refused.
