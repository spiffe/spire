---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Admin workload sends a time to live and the token value it chose
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: The Product creates the join token with that value
    kind: product
    actor: admin-workload
    entities:
      - {entity: join-token, effect: creates, facts: [Token, Expires at]}
    contexts:
      api: { place: "server-api::administration" }
---

# An admin workload supplies the token value

## Trigger

An admin workload provisions nodes with tokens it generates itself.

## Outcome

The join token exists with the supplied value; without one the Product
generates it.
