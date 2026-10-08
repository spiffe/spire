---
kind: validation
routes:
  api: Server API
steps:
  - text: The Agent asks for its authorized entries
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Agent is banned
    kind: condition
    actor: agent
    entities:
      - {entity: agent, effect: reads, facts: []}
    contexts:
      api: { place: "server-api::agents" }
  - text: The Product refuses the request as coming from a banned agent
    kind: product
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
---

# A banned agent shuts down

## Trigger

An agent that was banned tries to sync.

## Outcome

The request is refused; the agent removes its SVID and shuts down.

## Edge cases

- An agent evicted, expired or holding a replaced SVID is told so; it re-attests when its attestor allows, and otherwise removes its SVID and shuts down.
