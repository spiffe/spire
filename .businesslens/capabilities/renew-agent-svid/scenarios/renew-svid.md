---
kind: primary
routes:
  api: Server API
steps:
  - text: "The Agent asks for a new SVID, authenticating with its current one"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Product signs a new agent SVID and keeps it as the pending SVID
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: changes, from: Attested, to: Attested, facts: [Pending SVID]}
    contexts:
      api: { place: "server-api::agents" }
  - text: The Agent authenticates with the new SVID for the first time
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: "The Product makes the pending SVID the agent's accepted one"
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: changes, from: Attested, to: Attested, facts: [Serial number, Expiration time, Pending SVID]}
    contexts:
      api: { place: "server-api::agents" }
---

# Renew the agent SVID

## Trigger

The agent SVID has passed about half of its lifetime, or was signed by a
tainted authority.

## Outcome

The agent holds a new SVID and the server accepts only its serial from then
on.

## Edge cases

- Until the agent uses the new SVID, the server accepts both the current and the pending one.
- If the SVID already expired and renewal fails, the agent cannot recover without attesting again.
