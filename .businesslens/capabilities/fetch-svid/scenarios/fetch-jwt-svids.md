---
kind: alternative
routes:
  wapi: Workload API
steps:
  - text: "The Workload asks for a JWT token, naming audiences and optionally one of its SPIFFE IDs"
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: The Product attests the calling process and finds its matching registration entries
    kind: product
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, JWT-SVID TTL, JWT-SVID include JTI]}
    contexts:
      wapi: { place: workload-api }
  - text: "The Product returns an unexpired cached JWT-SVID for the same audiences, or has a new one signed"
    kind: product
    actor: workload
    entities:
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at, Hint]}
    contexts:
      wapi: { place: workload-api }
---

# Fetch JWT-SVIDs

## Trigger

A workload must present a token to a service.

## Outcome

The workload holds a JWT-SVID for the audiences for each of its identities, or
for the one asked for.

## Edge cases

- Asking for a SPIFFE ID the caller does not hold is refused with "no identity issued".
- A cached token is reused until half of its lifetime has passed, unless its entry includes a JTI.
- When signing fails, a cached token that has not expired is returned; otherwise the request is refused as unavailable.
