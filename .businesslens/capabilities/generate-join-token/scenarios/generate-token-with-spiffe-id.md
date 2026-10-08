---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator asks for a token and names a SPIFFE ID
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates the join token and a registration entry for the chosen SPIFFE ID whose parent is the ID derived from the token
    kind: product
    actor: operator
    entities:
      - {entity: join-token, effect: creates, facts: [Token, Expires at]}
      - {entity: registration-entry, effect: creates, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, Revision, Created at], with: join-token}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Generate a join token with a SPIFFE ID

## Trigger

An Operator wants the node that uses the token to also carry a readable SPIFFE
ID.

## Outcome

The token exists, and a registration entry gives the agent that uses it the
chosen SPIFFE ID as a node alias.

## Edge cases

- An invalid SPIFFE ID is refused before the token is created.
