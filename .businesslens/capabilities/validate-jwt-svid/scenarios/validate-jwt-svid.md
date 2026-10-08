---
kind: primary
routes:
  wapi: Workload API
steps:
  - text: The Workload submits the token and the audience it expects
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: "The Product verifies the signature, expiry and audience against the bundles the caller trusts"
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, JWT authorities]}
    contexts:
      wapi: { place: workload-api }
  - text: The Product returns the SPIFFE ID and claims
    kind: product
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
---

# Validate a JWT-SVID

## Trigger

A workload receives a JWT-SVID from a peer.

## Outcome

The workload learns the token's SPIFFE ID and claims; claims of tokens from
foreign trust domains are limited to the subject, expiry and audience and
those the agent allows.
