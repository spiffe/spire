---
appliesTo:
  - type: capability
    id: attest-agent
  - type: capability
    id: renew-agent-svid
references:
  - kind: code
    role: implementation
    target: pkg/server/plugin/nodeattestor/base/base.go
---

# Trust-on-first-use evidence attests a node only once

Evidence from node attestors that trust on first use admits a node only while
it has no agent record; such agents cannot re-attest and renew their SVID
instead.
