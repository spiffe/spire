---
kind: alternative
routes:
  wapi: Workload API
steps:
  - text: The Workload opens a stream for trust material
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: No registration entry matches the caller and the allow_unauthenticated_verifiers setting is on
    kind: condition
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [Selectors]}
    contexts:
      wapi: { place: workload-api }
  - text: The Product returns only the bundle of its own trust domain
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities, JWT authorities]}
    contexts:
      wapi: { place: workload-api }
---

# An unauthenticated verifier fetches the agent's bundle

## Trigger

A process without an identity needs to verify peers, and the agent's
`allow_unauthenticated_verifiers` setting is on.

## Outcome

The process holds the agent's own trust domain bundle; without the setting it
is refused with "no identity issued".
