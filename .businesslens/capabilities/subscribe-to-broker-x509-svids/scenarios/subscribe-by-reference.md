---
kind: primary
routes:
  brk: SPIFFE Broker API
steps:
  - text: "The Broker sends a reference, such as a pod or a process, of a type it is allowed to use"
    kind: actor
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
  - text: "The Product attests the reference and streams the X.509-SVIDs of its matching registration entries, except admin and downstream entries"
    kind: product
    actor: broker
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, Admin, Downstream, Hint]}
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      brk: { place: broker-api }
---

# Subscribe to a referenced workload's X.509-SVIDs

## Trigger

A broker, such as a node-level proxy, acts for a workload it can identify by
reference.

## Outcome

The broker holds the workload's X.509-SVIDs and receives each rotation.

## Edge cases

- A request without a reference is refused.
- A reference type no workload attestor understands is refused as not implemented.
- Of two entries with the same hint, only the older one's identity is sent.
