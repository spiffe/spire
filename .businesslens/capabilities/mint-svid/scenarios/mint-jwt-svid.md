---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator supplies the SPIFFE ID, at least one audience and an optional time to live"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product signs the JWT-SVID with the active JWT authority
    kind: product
    actor: operator
    entities:
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at, Hint]}
      - {entity: jwt-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Mint a JWT-SVID

## Trigger

An Operator needs a token for software SPIRE does not attest.

## Outcome

The Operator holds the JWT-SVID, printed or written to a file.

## Edge cases

- Without an audience the request is refused.
- While the server has JWT-SVIDs disabled the request is refused as "JWT functionality is disabled".
