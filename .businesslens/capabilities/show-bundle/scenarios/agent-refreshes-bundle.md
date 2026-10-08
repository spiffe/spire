---
kind: alternative
routes:
  api: Server API
steps:
  - text: "The Agent asks for the server's trust material at its sync"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: "The Product returns the server's own bundle with the authorities marked tainted"
    kind: product
    actor: agent
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities, Refresh hint, Sequence number]}
    contexts:
      api: { place: "server-api::agents" }
---

# An attested agent refreshes the bundle

## Trigger

The agent's sync interval elapses.

## Outcome

The Agent serves the current bundle to its workloads and replaces every SVID
signed by an authority now marked tainted.
