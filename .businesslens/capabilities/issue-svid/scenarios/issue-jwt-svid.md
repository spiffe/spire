---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Agent names an authorized entry and at least one audience
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Product signs a JWT-SVID for the entry with the active JWT authority
    kind: product
    actor: agent
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, JWT-SVID TTL, JWT-SVID include JTI]}
      - {entity: jwt-authority, effect: reads, facts: [Authority ID]}
      - {entity: jwt-svid, effect: creates, facts: [SPIFFE ID, Token, Audience, Expires at]}
    contexts:
      api: { place: "server-api::agents" }
---

# Issue a JWT-SVID for an authorized entry

## Trigger

A workload asks its agent for a JWT-SVID the agent has no valid cached copy
of.

## Outcome

The agent holds the JWT-SVID and passes it on.

## Edge cases

- Without an audience the request is refused with "at least one audience is required".
- While the server has JWT-SVIDs disabled the request is refused as "JWT functionality is disabled".
