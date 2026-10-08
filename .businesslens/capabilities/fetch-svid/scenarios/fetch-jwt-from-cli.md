---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: The Operator names the audiences and optionally a SPIFFE ID
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: "The Product attests the command's process and returns a JWT-SVID for its matching entries with the JWT bundles"
    kind: product
    actor: operator
    entities:
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at, Hint]}
      - {entity: bundle, effect: reads, facts: [Trust domain, JWT authorities]}
    contexts:
      cli: { place: agent-cli }
---

# Fetch a JWT-SVID from the command line

## Trigger

An Operator needs a token for testing on a node.

## Outcome

The Operator sees the JWT-SVIDs and the JWT bundles.
