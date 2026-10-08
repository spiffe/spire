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
  - kind: code
    role: implementation
    target: "pkg/server/endpoints/middleware.go#AgentAuthorizer"
  - kind: code
    role: implementation
    target: pkg/agent/svid/rotator.go
---

# Renew the agent SVID

An agent whose attestation cannot be repeated renews its agent SVID with its
current one before half of its lifetime has passed. Agents that can re-attest
re-attest instead.
