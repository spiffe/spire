---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names an authority that is active, prepared or not yet tainted"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product refuses the request and changes nothing
    kind: product
    actor: operator
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# An authority that is not tainted cannot be revoked

## Trigger

An Operator tries to revoke an authority before tainting it.

## Outcome

Nothing changes; only a tainted, old authority can be revoked.
