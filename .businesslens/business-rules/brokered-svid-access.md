---
appliesTo:
  - type: entity
    id: x509-svid
    effect: reads
    contexts:
      - place: broker-api
permits:
  - actors:
      - broker
references:
  - kind: code
    role: implementation
    target: pkg/agent/broker/api/service.go
---

# Only admitted brokers receive X.509-SVIDs through the SPIFFE Broker API

The broker must present a SPIFFE ID the agent's broker configuration lists and
a reference type it is allowed to use, over TCP only where that is allowed,
and the agent must attest the reference.
