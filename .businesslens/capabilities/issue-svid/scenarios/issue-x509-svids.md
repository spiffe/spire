---
kind: primary
routes:
  api: Server API
steps:
  - text: "The Agent sends a certificate signing request for each entry whose X.509 identity is missing, due or changed"
    kind: actor
    actor: agent
    entities: []
    contexts:
      api: { place: "server-api::agents" }
  - text: The Product signs an X.509-SVID for each authorized entry with the active X.509 authority
    kind: product
    actor: agent
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, DNS names, X509-SVID TTL]}
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
      - {entity: x509-svid, effect: creates, facts: [SPIFFE ID, Certificate chain, DNS names, Expires at]}
    contexts:
      api: { place: "server-api::agents" }
---

# Issue X.509-SVIDs for authorized entries

## Trigger

An entry is new or changed, or its X.509-SVID passed about half of its
lifetime or was signed by a tainted authority.

## Outcome

The agent holds a fresh X.509-SVID per entry; each result succeeds or fails on
its own.

## Edge cases

- An entry the agent is not authorized for is refused with "entry not found or not authorized".
- Entries that disable X.509-SVID prefetch are signed only once a workload asks for them.
