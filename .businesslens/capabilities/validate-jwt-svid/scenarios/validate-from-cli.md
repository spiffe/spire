---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator supplies the token and audience
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: "The Product validates the token against the bundles the command's process trusts and returns the result"
    kind: product
    actor: operator
    entities:
      - {entity: bundle, effect: reads, facts: [JWT authorities]}
    contexts:
      cli: { place: agent-cli }
---

# Validate a JWT-SVID from the command line

## Trigger

An Operator checks a token on a node.

## Outcome

The Operator sees the SPIFFE ID and claims, or that the SVID is not valid.
