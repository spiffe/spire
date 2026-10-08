---
kind: alternative
routes:
  api: Server API
steps:
  - text: "The Agent asks for the server's trust material"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: "The Product returns the server's own bundle"
    kind: product
    actor: agent
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::bootstrap" }
---

# An agent fetches the bundle before attesting

## Trigger

An agent starts its node attestation.

## Outcome

The Agent holds the current bundle of the server's trust domain.
