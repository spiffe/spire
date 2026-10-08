---
availability:
  - place: server-cli
  - place: "server-api::administration"
  - place: agent-cli
references:
  - kind: code
    role: implementation
    target: pkg/server/api/debug/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/api/debug/v1/service.go
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/debug/debug.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server debug getinfo
---

# Get debug information

Show a running server's or agent's uptime, its own SVID chain, and counts of
what it holds.
