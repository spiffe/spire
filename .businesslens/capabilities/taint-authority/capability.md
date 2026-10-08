---
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/localauthority/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server localauthority
  - kind: code
    role: implementation
    target: pkg/agent/manager/sync.go
---

# Taint an authority

Mark the old X.509 or JWT authority, or an upstream authority that signed the
old X.509 authority, as no longer trusted for signing, so agents, downstream
servers and the server itself replace everything it signed. Upstream
authorities can be tainted only while one is configured, and local X.509
authorities only while none is.
