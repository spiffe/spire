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
    target: cmd/spire-server/cli/agent/list.go
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/agent/show.go
---

# List agents

List attested agents, filtered by selectors, attestation type, whether they
can re-attest, whether they are banned or when they expire, or show one agent
with its node selectors.
