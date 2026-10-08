---
appliesTo:
  - type: entity
    id: bundle
    effect: reads
    contexts:
      - place: workload-api
      - place: agent-cli
      - place: envoy-sds
permits:
  - actors:
      - workload
      - operator
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
---

# A workload receives only the bundles of its own and its entries' federated trust domains

A workload needs an identity to receive bundles; it receives its trust
domain's bundle and those of the trust domains its matching entries federate
with. When the agent allows unauthenticated verifiers, a process without an
identity receives the agent's own trust domain bundle only.
