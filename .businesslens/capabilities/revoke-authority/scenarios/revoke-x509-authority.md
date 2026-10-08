---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the tainted X.509 authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the authority from the bundle
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, effect: removes, from: Tainted}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Revoke a tainted X.509 authority

## Trigger

An Operator has confirmed that every SVID signed by a tainted authority has
been replaced.

## Outcome

The authority is gone from the bundle and its removal propagates to agents and
federated trust domains.

## Edge cases

- While an upstream authority is configured, local X.509 authorities cannot be revoked.
