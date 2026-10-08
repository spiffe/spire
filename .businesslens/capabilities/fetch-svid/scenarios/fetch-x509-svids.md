---
kind: primary
routes:
  wapi: Workload API
steps:
  - text: The Workload opens a stream for its X.509 identities
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: The Product attests the calling process and finds the registration entries whose selectors it matches
    kind: product
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, Hint, Federates with]}
    contexts:
      wapi: { place: workload-api }
  - text: "The Product returns an X.509-SVID for each match, with the bundle of its trust domain and the federated bundles"
    kind: product
    actor: workload
    entities:
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      wapi: { place: workload-api }
---

# Fetch X.509-SVIDs

## Trigger

A workload starts and needs its identities for mTLS.

## Outcome

The workload holds an X.509-SVID with key for each matching entry and the
bundles to verify peers; the stream stays open.

## Edge cases

- Of two entries with the same hint, only the older entry's identity is returned.
- When attestation of the caller fails the request is refused as unavailable.
- Entries that store their SVIDs in an SVID store are never served here.
