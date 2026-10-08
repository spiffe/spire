---
kind: system
acts: external
references:
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Delegated Identity API
---

# Authorized delegate

A privileged workload, attested like any other, whose SPIFFE ID the agent's
`authorized_delegates` setting lists. It obtains identities on behalf of other
processes on the node and can impersonate any of them.
