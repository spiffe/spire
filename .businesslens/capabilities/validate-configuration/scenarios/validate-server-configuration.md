---
kind: primary
routes:
  cli: Server CLI
steps:
  - text: The Operator names the configuration file of the SPIRE Server
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
  - text: The Product loads it and asks each configured plugin to validate its settings
    kind: product
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
---

# Validate the server configuration

## Trigger

An Operator changed a server configuration.

## Outcome

The Operator sees that the configuration is valid, or each error and note per
plugin.

## Edge cases

- Plugin validation that takes too long fails.
