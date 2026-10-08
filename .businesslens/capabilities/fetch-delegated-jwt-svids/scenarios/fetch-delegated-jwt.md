---
kind: primary
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate names audiences and the selectors or process ID
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: The Product returns a JWT-SVID for each matching registration entry other than admin and downstream entries
    kind: product
    actor: authorized-delegate
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, Admin, Downstream]}
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at, Hint]}
    contexts:
      del: { place: delegated-identity-api }
---

# Fetch delegated JWT-SVIDs

## Trigger

An authorized delegate must present a token on behalf of a process.

## Outcome

The delegate holds a JWT-SVID for each matching entry.

## Edge cases

- Without an audience the request is refused.
- A process that matches no entry gets no token.
