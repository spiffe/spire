---
appliesTo:
  - type: context
    context:
      place: broker-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/broker/api/service.go
---

# Only configured brokers obtain identities by reference

The SPIFFE Broker API serves only callers whose SPIFFE ID the agent's broker
configuration lists, for the reference types it allows them, and never hands
out admin or downstream identities.
