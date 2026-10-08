---
kind: validation
routes:
  oidc: OIDC Discovery Provider
steps:
  - text: The OIDC-authenticated system requests the discovery document for a domain not configured
    kind: actor
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
  - text: The Product refuses because the domain is not allowed
    kind: product
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
---

# A domain that is not allowed is refused

## Trigger

The discovery document is requested for a host outside the configured domains.

## Outcome

The request is refused: the domain is not allowed.
