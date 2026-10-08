---
kind: system
acts: external
references:
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: SPIFFE Broker API
---

# Broker

Software listed in the agent's experimental `broker` configuration, such as a
node-level proxy, that authenticates with its own SPIFFE ID and obtains
identities for workloads it names by reference, for example by pod or process.
