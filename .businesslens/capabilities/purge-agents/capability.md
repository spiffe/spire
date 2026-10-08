---
domain: agents
availability:
  - place: server-cli
references:
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/agent/purge.go
---

# Purge agents

Remove, from the command line, agents that can re-attest and whose SVID
expired longer ago than a chosen time (30 days by default), or list them
without removing anything.
