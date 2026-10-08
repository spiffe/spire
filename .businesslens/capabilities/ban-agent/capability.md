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
    target: cmd/spire-server/cli/agent/ban.go
---

# Ban an agent

Stop an attested agent from acting and from attesting again. The record stays,
without an accepted SVID, so the ban holds until the agent is evicted.
