---
kind: validation
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator supplies a parent ID, SPIFFE ID and selectors"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "A registration entry with the same parent ID, SPIFFE ID and selectors already exists"
    kind: condition
    actor: operator
    entities:
      - {entity: registration-entry, effect: reads, facts: [Parent ID, SPIFFE ID, Selectors]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product refuses with \"similar entry already exists\" and returns the existing entry"
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: reads, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# A similar registration entry already exists

## Trigger

An Operator creates an entry whose parent ID, SPIFFE ID and selectors equal an
existing one's.

## Outcome

Nothing is created; the Product reports that a similar entry already exists
and returns the existing one.
