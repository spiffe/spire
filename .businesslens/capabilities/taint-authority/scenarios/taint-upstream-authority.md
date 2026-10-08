---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator names the upstream authority's subject key ID"
    kind: actor
    actor: operator
    entities:
      - {entity: upstream-authority, effect: reads, facts: [Subject key ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product marks the upstream authority tainted in the bundle
    kind: product
    actor: operator
    entities:
      - {entity: upstream-authority, effect: changes, from: Trusted, to: Tainted, facts: []}
      - {entity: bundle, effect: changes, facts: [X.509 authorities, Sequence number]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Taint an upstream authority

## Trigger

The upstream CA rotated and an Operator wants its previous certificate
distrusted.

## Outcome

The upstream authority is tainted; the server and its downstream servers
rotate away from authorities it signed, and agents replace what those signed.

## Edge cases

- Without an upstream authority configured the request is refused with "upstream authority is not configured".
- Only an upstream authority that signed the old X.509 authority can be tainted, never the one signing the active authority.
