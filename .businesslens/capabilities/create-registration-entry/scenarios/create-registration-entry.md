---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "The Operator supplies the SPIFFE ID, parent ID, selectors and optional SVID settings"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product creates the registration entry and returns it
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: creates, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Create a registration entry

## Trigger

An Operator wants software matching some selectors under a parent to receive a
SPIFFE ID.

## Outcome

The registration entry exists with a generated or chosen Entry ID, and agents
authorized for it begin issuing its identity at their next sync.

## Edge cases

- A SPIFFE ID or parent ID outside the server's trust domain, no selectors, invalid DNS names or a hint longer than 1024 characters are refused as invalid.
- Federating with a trust domain the server holds no bundle for is refused.
- Storing SVIDs requires every selector to be of the same type.
