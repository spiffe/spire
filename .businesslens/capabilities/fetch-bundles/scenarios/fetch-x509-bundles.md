---
kind: primary
routes:
  wapi: Workload API
steps:
  - text: The Workload opens a stream for X.509 trust material
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: "The Product returns the X.509 authorities of its trust domain and of the federated trust domains the caller's entries name"
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
      - {entity: registration-entry, effect: reads, facts: [Federates with]}
    contexts:
      wapi: { place: workload-api }
---

# Fetch X.509 bundles

## Trigger

A workload only verifies peers and needs CA certificates.

## Outcome

The workload holds the X.509 authorities of each trust domain it trusts and
receives each change.

## Edge cases

- An update identical to the last one is not sent again.
