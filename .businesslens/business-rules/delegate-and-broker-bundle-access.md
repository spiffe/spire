---
appliesTo:
  - type: entity
    id: bundle
    effect: reads
    contexts:
      - place: delegated-identity-api
      - place: broker-api
permits:
  - actors:
      - authorized-delegate
      - broker
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/broker/api/service.go
---

# Only authorized delegates and admitted brokers receive every bundle the agent holds

The Delegated Identity API and the SPIFFE Broker API hand out every bundle the
agent holds, but only to an authorized delegate or a broker whose reference
the agent resolved.
