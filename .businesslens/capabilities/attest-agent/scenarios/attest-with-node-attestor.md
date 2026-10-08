---
kind: primary
routes:
  api: Server API
steps:
  - text: "The Agent presents its node attestor's evidence and a certificate signing request"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: "The Product verifies the evidence through the matching node attestor, answering any challenge"
    kind: product
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product records the agent with its node selectors and signs its agent SVID
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: creates, to: Attested, facts: [SPIFFE ID, Attestation type, Node selectors, Serial number, Expiration time, Pending SVID, Can re-attest, Agent version]}
    contexts:
      api: { place: "server-api::bootstrap" }
---

# Attest a node with platform evidence

## Trigger

An agent starts without an SVID on disk.

## Outcome

The agent is attested with the node selectors its attestor established and
holds an agent SVID.

## Edge cases

- An attestation type the server has no node attestor for is refused.
- An agent ID equal to the server's own ID is refused.
