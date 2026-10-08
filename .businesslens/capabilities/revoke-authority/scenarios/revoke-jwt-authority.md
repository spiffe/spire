---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the tainted JWT authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: jwt-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the authority from the bundle
    kind: product
    actor: operator
    entities:
      - {entity: jwt-authority, effect: removes, from: Tainted}
      - {entity: bundle, effect: changes, facts: [JWT authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Revoke a tainted JWT authority

## Trigger

An Operator has confirmed that every JWT-SVID signed by a tainted authority
has expired or been replaced.

## Outcome

The key is gone from the bundle and JWT-SVIDs it signed no longer verify.
