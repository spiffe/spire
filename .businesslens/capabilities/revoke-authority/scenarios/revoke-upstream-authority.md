---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the tainted upstream authority's subject key ID"
    kind: actor
    actor: operator
    entities:
      - {entity: upstream-authority, effect: reads, facts: [Subject key ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the upstream authority from the bundle
    kind: product
    actor: operator
    entities:
      - {entity: upstream-authority, effect: removes, from: Tainted}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Revoke a tainted upstream authority

## Trigger

An Operator has confirmed nothing still depends on a tainted upstream
authority.

## Outcome

The upstream authority is gone from the bundle.

## Edge cases

- Without an upstream authority configured the request is refused.
