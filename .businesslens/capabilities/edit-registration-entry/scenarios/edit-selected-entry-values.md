---
kind: alternative
routes:
  api: Server API
steps:
  - text: The Admin workload sends the entry with the values to change and names them in the request
    kind: actor
    actor: admin-workload
    entities: []
    contexts:
      api: { place: "server-api::administration" }
  - text: The Product changes only the named values and raises the revision
    kind: product
    actor: admin-workload
    entities:
      - {entity: registration-entry, effect: changes, facts: [SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision]}
    contexts:
      api: { place: "server-api::administration" }
---

# Edit selected values of a registration entry

## Trigger

An admin workload changes some values of an entry without knowing the others.

## Outcome

The named values change; every other value and the creation time are kept.
