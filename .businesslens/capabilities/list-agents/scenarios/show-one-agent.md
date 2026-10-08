---
kind: alternative
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
  - text: The Product returns the agent with its node selectors
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID, Attestation type, Node selectors, Serial number, Expiration time, Can re-attest, Agent version]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Show one agent

## Trigger

An Operator wants the details of one agent.

## Outcome

The Operator sees the agent's details including its node selectors.

## Edge cases

- An unknown agent is refused with "agent not found".
