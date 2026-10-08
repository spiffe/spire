---
domain: logger
availability:
  - place: server-cli
  - place: "server-api::administration"
  - place: agent-cli
references:
  - kind: code
    role: implementation
    target: pkg/server/api/logger/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/api/logger/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server logger
---

# Get the logger

Show the current and launch logging levels of a running server or agent.
