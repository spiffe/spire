---
kind: primary
routes:
  oidc: OIDC Discovery Provider
steps:
  - text: The OIDC-authenticated system requests the signing keys
    kind: actor
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
  - text: The Product returns the JWT authorities of the bundle it last polled as a key set
    kind: product
    actor: oidc-authenticated-system
    entities:
      - {entity: bundle, effect: reads, facts: [JWT authorities]}
    contexts:
      oidc: { place: oidc-discovery-provider }
---

# Fetch the signing keys

## Trigger

An OIDC-authenticated system verifies a JWT-SVID.

## Outcome

The system holds the current JWT authorities as a key set.

## Edge cases

- A failed poll keeps the keys from the last successful one.
