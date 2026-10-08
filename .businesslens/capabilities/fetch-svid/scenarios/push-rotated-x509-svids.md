---
kind: unattended
routes:
  wapi: Workload API
steps:
  - text: "An X.509-SVID is due for rotation, its registration entry changed, or its authority was tainted"
    kind: condition
    unattended: true
    entities:
      - {entity: x509-svid, effect: reads, facts: [Expires at]}
      - {entity: registration-entry, effect: reads, facts: [Revision]}
    contexts:
      wapi: { place: workload-api }
  - text: The Product obtains a replacement X.509-SVID
    kind: product
    entities:
      - {entity: x509-svid, effect: creates, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
    contexts:
      wapi: { place: workload-api }
  - text: The Product sends the replacement on every open stream entitled to it
    kind: product
    entities:
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
    contexts:
      wapi: { place: workload-api }
---

# Rotated X.509-SVIDs reach open streams

## Trigger

An X.509-SVID passes about half of its lifetime, its registration entry
changes, or its authority is tainted.

## Outcome

Every workload with an open stream receives the replacement before the old
SVID expires.

## Edge cases

- A workload that loses every matching entry has its stream ended with "no identity issued".
