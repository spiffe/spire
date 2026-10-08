---
domain: agents
availability:
  - place: "server-api::agents"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/agent/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server agent
---

# Post agent status

An attested agent reports its SPIRE version, which the server keeps on its
record.
