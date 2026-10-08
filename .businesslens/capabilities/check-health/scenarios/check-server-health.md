---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks whether the server is healthy
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product checks that it can read its own bundle and answers serving or not serving
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Check the server's health

## Trigger

An Operator or a script checks a SPIRE Server.

## Outcome

The Operator learns whether the server is healthy; a server that cannot read
its own bundle is not serving.
