---
kind: alternative
routes:
  wapi: Workload API
steps:
  - text: The Workload opens a stream for JWT trust material
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: "The Product returns the JWT authorities of its trust domain and of the federated trust domains the caller's entries name"
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, JWT authorities]}
      - {entity: registration-entry, effect: reads, facts: [Federates with]}
    contexts:
      wapi: { place: workload-api }
---

# Fetch JWT bundles

## Trigger

A workload verifies JWT-SVIDs itself.

## Outcome

The workload holds the JWT authorities, as JWKS, of each trust domain it
trusts and receives each change.
