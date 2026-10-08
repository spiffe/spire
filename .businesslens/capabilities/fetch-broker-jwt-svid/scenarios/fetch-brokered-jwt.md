---
kind: primary
routes:
  brk: SPIFFE Broker API
steps:
  - text: The Broker sends a reference and the audiences
    kind: actor
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
  - text: The Product attests the reference and returns a JWT-SVID for each of its matching entries other than admin and downstream entries
    kind: product
    actor: broker
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, Admin, Downstream]}
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at, Hint]}
    contexts:
      brk: { place: broker-api }
---

# Fetch a referenced workload's JWT-SVID

## Trigger

A broker must present a token on behalf of a workload.

## Outcome

The broker holds the JWT-SVIDs.

## Edge cases

- A workload that matches no entry gets no token.
