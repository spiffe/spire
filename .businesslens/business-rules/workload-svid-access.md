---
appliesTo:
  - type: entity
    id: x509-svid
    effect: reads
    contexts:
      - place: workload-api
      - place: agent-cli
      - place: envoy-sds
permits:
  - actors:
      - workload
      - operator
  - unattended: true
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
---

# A workload receives only the X.509-SVIDs of entries its selectors match

The agent attests the calling process into selectors and serves only the
registration entries, among those it is authorized for, whose selectors are
all among them. The agent itself rotates the X.509-SVIDs it holds and sends
each replacement to the streams entitled to it.
