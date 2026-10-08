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
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/agent/evict.go
  - kind: code
    role: implementation
    target: pkg/server/node/manager.go
---

# Evict an agent

Remove an agent's record and node selectors so it is no longer attested. An
evicted agent, banned or not, may attest again with fresh evidence. The server
also prunes expired agents on its own when configured to.
