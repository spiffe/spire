---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the old X.509 authority's ID"
    kind: actor
    actor: operator
    entities:
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The server is configured with an upstream authority
    kind: condition
    actor: operator
    entities:
      - {entity: server-configuration, effect: reads, facts: [Upstream authority]}
      - {entity: upstream-authority, effect: reads, facts: [Subject key ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product refuses the request and changes nothing
    kind: product
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Local X.509 authorities are not tainted while an upstream authority is configured

## Trigger

An Operator of a server with an upstream authority tries to taint a local
X.509 authority.

## Outcome

Nothing changes; the upstream authority is tainted instead.
