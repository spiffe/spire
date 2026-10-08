---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator chooses filters or an Entry ID
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product returns the matching registration entries
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: reads, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Show registration entries

## Trigger

An Operator wants to see which registration entries exist.

## Outcome

The Operator sees every matching entry with its values.

## Edge cases

- Selector and federated trust domain filters match exactly, any, a superset or a subset; superset is the default.
- Combining an Entry ID with other filters is refused by the command line.
- An unknown Entry ID is refused with "entry not found".
