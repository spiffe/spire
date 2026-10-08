---
domain: agents
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/agent/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server agent
---

# Count agents

Report how many agents are attested, optionally narrowed by the same filters
as listing them.
