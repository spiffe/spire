---
kind: primary
routes:
  oidc: OIDC Discovery Provider
steps:
  - text: The OIDC-authenticated system requests the discovery document for an allowed domain
    kind: actor
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
  - text: "The Product returns the issuer, configured or derived from the requested host, and the keys location"
    kind: product
    actor: oidc-authenticated-system
    entities: []
    contexts:
      oidc: { place: oidc-discovery-provider }
---

# Fetch the discovery document

## Trigger

An OIDC-authenticated system is configured to trust the trust domain as an
OIDC issuer.

## Outcome

The system knows the issuer, the keys location and that ID tokens are signed
with RS256, ES256 or ES384.

## Edge cases

- A configured issuer and keys location take precedence over those derived from the request.
- Methods other than GET are refused.
