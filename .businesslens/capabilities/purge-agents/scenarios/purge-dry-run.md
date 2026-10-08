---
kind: alternative
routes:
  cli: Server CLI
steps:
  - text: The Operator asks for a dry run
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
  - text: The Product lists the re-attestable agents expired for longer than the chosen time
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID, Expiration time, Can re-attest]}
    contexts:
      cli: { place: server-cli }
---

# Preview a purge

## Trigger

An Operator wants to see which agents a purge would remove.

## Outcome

The Operator sees the agents that would be removed; nothing is removed.
