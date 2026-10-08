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
  - text: The Product marks the agent banned by dropping its accepted and pending SVIDs
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: changes, from: Attested, to: Banned, facts: [Serial number, Pending SVID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Ban an attested agent

## Trigger

An Operator suspects a node is compromised.

## Outcome

The agent is banned: the server refuses its requests and its attempts to
attest, and the agent deletes its SVID and shuts down when told it is banned.

## Edge cases

- An unknown agent is refused with "agent not found".
