---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Agent names a foreign trust domain its entries federate with
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: "The Product returns that trust domain's bundle"
    kind: product
    actor: agent
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::agents" }
---

# An agent fetches a federated bundle

## Trigger

An agent's entries federate with a foreign trust domain.

## Outcome

The agent delivers the federated bundle to the workloads whose entries
federate with it.

## Edge cases

- A trust domain the server holds no bundle for is reported as not found, and the agent skips it.
