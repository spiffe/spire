---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator identifies the entry by its Entry ID and supplies all its new values
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: "The Product replaces the registration entry's values and raises its revision"
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: changes, facts: [SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Edit a registration entry

## Trigger

An Operator wants an existing entry to issue a different identity or under
different settings.

## Outcome

The entry carries the new values and a higher revision, so agents replace the
SVIDs they issued from it; values the command line was not given are reset.

## Edge cases

- An unknown Entry ID is refused with "entry not found"; an edit never creates an entry.
- Without the Entry ID, SPIFFE ID, parent ID and a selector the command line refuses before sending.
- Given only the prefetch or JTI setting, the command line keeps the entry's other additional attributes.
