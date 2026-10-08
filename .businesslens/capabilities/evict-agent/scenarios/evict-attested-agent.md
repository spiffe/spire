---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the agent's SPIFFE ID"
    kind: actor
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the agent and its node selectors
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: removes, from: Attested}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Evict an agent

## Trigger

An Operator wants a node to be de-attested.

## Outcome

The agent record and its node selectors are gone; the agent must attest again
to act.

## Edge cases

- For an agent attested with a join token, the registration entry created with that token is removed too; other entries under the agent are kept.
- An unknown agent is refused with "agent not found".
