---
kind: primary
routes:
  api: Server API
steps:
  - text: "The Agent asks for its authorized entries, sending the revisions it already holds"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: "The Product returns the registration entries the agent is authorized for that are new or changed, and the IDs of the rest"
    kind: product
    actor: agent
    entities:
      - {entity: registration-entry, effect: reads, facts: [Entry ID, SPIFFE ID, Parent ID, Selectors, X509-SVID TTL, JWT-SVID TTL, Federates with, Admin, Downstream, DNS names, Hint, Entry expiry, Store SVID, Disable X509-SVID prefetch, JWT-SVID include JTI, Revision, Created at]}
    contexts:
      api: { place: "server-api::agents" }
---

# Sync authorized entries

## Trigger

The agent's sync interval, five seconds by default, elapses.

## Outcome

The agent holds the current entries for its node and drops those no longer
authorized.

## Edge cases

- A first sync cannot ask for particular entry IDs.
- A node alias applies only while the agent's node selectors include all of its selectors.
