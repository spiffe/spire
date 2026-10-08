---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator chooses PEM or SPIFFE format
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product returns the server's own bundle"
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Show the server's bundle

## Trigger

An Operator needs the trust domain's CA certificates, for example to bootstrap
an agent.

## Outcome

The Operator sees the server's bundle in the chosen format.
