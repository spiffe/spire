---
kind: validation
routes:
  api: Server API
steps:
  - text: The Agent presents evidence for a node that already has an agent record
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::bootstrap" }
  - text: The Product refuses because the attestation data has already been used
    kind: product
    actor: agent
    entities:
      - {entity: agent, effect: reads, facts: [SPIFFE ID, Can re-attest]}
    contexts:
      api: { place: "server-api::bootstrap" }
---

# Reused trust-on-first-use evidence is refused

## Trigger

An agent attests with evidence from an attestor that trusts on first use, such
as an AWS or GCP instance identity, for a node already attested.

## Outcome

The agent is not attested: "attestation data has already been used to attest
an agent".

## Edge cases

- Evicting the agent first lets the node attest again.
