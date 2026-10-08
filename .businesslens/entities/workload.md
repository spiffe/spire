---
kind: system
acts: external
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
---

# Workload

A running process on a node with an agent that asks for its own identities or
verifies its peers. The agent identifies it by attesting the calling process
into selectors; Envoy proxies fetching secrets are workloads too.
