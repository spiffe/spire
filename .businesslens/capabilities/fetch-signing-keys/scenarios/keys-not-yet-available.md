---
kind: edge
routes:
  oidc: OIDC Discovery Provider
steps:
  - text: The OIDC-authenticated system requests the signing keys
    kind: actor
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
  - text: The provider has not polled its key source successfully yet
    kind: condition
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
  - text: The Product reports that the document is not available
    kind: product
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
---

# Signing keys are not available yet

## Trigger

The keys are requested before the provider's first successful poll.

## Outcome

An error is returned instead of an empty or invented key set.

## Edge cases

- A bundle with no JWT authorities is reported as JWT not supported.
