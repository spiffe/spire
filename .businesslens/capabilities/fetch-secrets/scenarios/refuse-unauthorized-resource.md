---
kind: validation
routes:
  sds: Envoy SDS
steps:
  - text: The Workload asks for a SPIFFE ID or trust domain not among its identities or bundles
    kind: actor
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain]}
    contexts:
      sds: { place: envoy-sds }
  - text: The Product refuses because the workload is not authorized for the requested identities
    kind: product
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID]}
    contexts:
      sds: { place: envoy-sds }
---

# An identity Envoy does not hold is refused

## Trigger

Envoy asks for a resource name the Envoy process is not entitled to.

## Outcome

The request is refused as "workload is not authorized for the requested
identities".
