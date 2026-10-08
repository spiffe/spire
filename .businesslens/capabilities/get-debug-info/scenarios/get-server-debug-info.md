---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator asks for the server's debug information"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns its uptime, the number of agents, entries and bundles it holds, and its own SVID chain"
    kind: product
    actor: operator
    entities:
      - {entity: agent, effect: reads, facts: []}
      - {entity: registration-entry, effect: reads, facts: []}
      - {entity: bundle, effect: reads, facts: []}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Get the server's debug information

## Trigger

An Operator diagnoses a SPIRE Server.

## Outcome

The Operator sees the server's state at a glance.

## Edge cases

- The answer may be up to five seconds old.
