---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator chooses optional filters
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product returns the matching agents
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID, Attestation type, Expiration time, Serial number, Can re-attest]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# List attested agents

## Trigger

An Operator wants to see which nodes are attested.

## Outcome

The Operator sees each matching agent with its attestation type, expiry,
serial number or that it is banned, and whether it can re-attest.
