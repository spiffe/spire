---
kind: alternative
routes:
  sds: Envoy SDS
steps:
  - text: "The Workload asks for a validation context by trust domain, or by the own or all trust domains name"
    kind: actor
    actor: workload
    entities: []
    contexts:
      sds: { place: envoy-sds }
  - text: The Product returns the X.509 authorities of the trust domains named
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      sds: { place: envoy-sds }
---

# Fetch a validation context

## Trigger

Envoy needs the CA certificates to verify peers.

## Outcome

Envoy holds the validation context for the trust domains asked for, with
SPIFFE certificate validation unless it is disabled.

## Edge cases

- SPIFFE certificate validation is used for Envoy 1.18 and later unless disabled in the agent or in the Envoy node metadata.
