---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Agent presents fresh evidence and a certificate signing request
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: "The Product verifies the evidence, replaces the agent's node selectors and signs a new agent SVID"
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: changes, from: Attested, to: Attested, facts: [Node selectors, Serial number, Expiration time, Pending SVID, Can re-attest]}
    contexts:
      api: { place: "server-api::bootstrap" }
---

# Re-attest an attested agent

## Trigger

An agent whose attestor allows re-attestation rotates its SVID, or re-attests
after the server reported its SVID expired, unknown or replaced.

## Outcome

The agent record carries a new serial number, expiry and node selectors, and
any pending SVID is dropped.
