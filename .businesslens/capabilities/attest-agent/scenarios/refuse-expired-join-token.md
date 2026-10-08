---
kind: validation
routes:
  api: Server API
steps:
  - text: The Agent presents a join token past its expiry
    kind: actor
    actor: agent
    entities:
      - {entity: join-token, effect: reads, facts: [Token, Expires at]}
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product uses up the join token
    kind: product
    actor: agent
    entities:
      - {entity: join-token, effect: removes}
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product refuses because the token had expired
    kind: product
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
---

# An expired join token is refused

## Trigger

An agent presents a join token after its expiry.

## Outcome

The agent is not attested and the token is used up anyway.

## Edge cases

- An unknown or already used join token is refused with "join token does not exist or has already been used".
