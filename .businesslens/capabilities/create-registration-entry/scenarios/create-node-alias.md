---
kind: alternative
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator supplies a SPIFFE ID and node selectors and marks the entry as a node entry
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates a registration entry whose parent is the server itself
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: creates, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Create a node alias

## Trigger

An Operator wants every agent whose node selectors match to carry an
additional, shared SPIFFE ID.

## Outcome

Every agent whose node selectors include all the entry's selectors carries the
alias, and entries can name the alias as their parent.
