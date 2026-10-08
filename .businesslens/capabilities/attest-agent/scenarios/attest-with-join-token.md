---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Agent presents the join token and a certificate signing request
    kind: actor
    actor: agent
    entities:
      - {entity: join-token, effect: reads, facts: [Token]}
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product uses up the join token
    kind: product
    actor: agent
    entities:
      - {entity: join-token, effect: removes}
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product records the agent and signs its agent SVID
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: creates, to: Attested, facts: [SPIFFE ID, Attestation type, Node selectors, Serial number, Expiration time, Pending SVID, Can re-attest, Agent version]}
    contexts:
      api: { place: "server-api::bootstrap" }
---

# Attest a node with a join token

## Trigger

An agent is started with a join token an Operator generated.

## Outcome

The join token is used up and the agent is attested under an agent ID derived
from it; it cannot re-attest and renews its SVID instead.

## Edge cases

- A failure after the token is used up does not restore it.
