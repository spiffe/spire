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

# Set the log level

Change the logging level of a running server or agent without restarting it.
