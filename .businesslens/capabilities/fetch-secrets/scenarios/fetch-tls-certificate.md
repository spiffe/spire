---
kind: primary
routes:
  sds: Envoy SDS
steps:
  - text: The Workload asks for a TLS certificate by SPIFFE ID or by the default name
    kind: actor
    actor: workload
    entities: []
    contexts:
      sds: { place: envoy-sds }
  - text: The Product attests the Envoy process and finds its matching registration entries
    kind: product
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors]}
    contexts:
      sds: { place: envoy-sds }
  - text: "The Product returns the X.509-SVID named, or the first identity for the default name"
    kind: product
    actor: workload
    entities:
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
    contexts:
      sds: { place: envoy-sds }
---

# Fetch a TLS certificate

## Trigger

Envoy starts with a listener or cluster that needs a certificate from SPIRE.

## Outcome

Envoy holds the X.509-SVID with key and receives replacements on rotation.

## Edge cases

- Acknowledgements of stale versions are ignored.
- Incremental (delta) secret discovery is not implemented.
