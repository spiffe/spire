---
kind: primary
routes:
  api: Server API
steps:
  - text: The Agent reports its version
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Product records the version on the agent
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: changes, facts: [Agent version]}
    contexts:
      api: { place: "server-api::agents" }
---

# Report the agent version

## Trigger

An agent starts or reconnects to the server.

## Outcome

Listing or showing the agent shows the version it reported.

## Edge cases

- An empty version leaves the recorded one unchanged.
- A version longer than 255 characters is refused.
