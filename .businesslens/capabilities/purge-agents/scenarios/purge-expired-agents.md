---
kind: primary
routes:
  cli: Server CLI
steps:
  - text: The Operator chooses the expiry age to purge
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
  - text: The Product finds the re-attestable agents expired for longer than that
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID, Expiration time, Can re-attest]}
    contexts:
      cli: { place: server-cli }
  - text: The Product removes each one and reports the result per agent
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: removes, from: Attested}
    contexts:
      cli: { place: server-cli }
---

# Purge expired agents

## Trigger

An Operator cleans up records of nodes that are gone.

## Outcome

Each expired re-attestable agent is removed and reported as purged or not
purged; with none the Operator is told "No agents to purge."
