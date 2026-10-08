---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Admin workload sends a batch of entries to create over mutual TLS
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: The Product creates each registration entry and returns a result for each
    kind: product
    actor: admin-workload
    entities:
      - {entity: registration-entry, effect: creates, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      api: { place: "server-api::administration" }
---

# An admin workload creates registration entries

## Trigger

An admin workload, such as a controller reconciling a cluster, needs
identities registered.

## Outcome

Each valid entry exists exactly as when an Operator creates it; invalid ones
are reported individually.
