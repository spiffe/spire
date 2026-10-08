---
domain: federation
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/trustdomain/v1/service.go
  - kind: code
    role: implementation
    target: pkg/server/api/trustdomain.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Federation configuration
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/federation/create.go
---

# Create a federation relationship

Federate with a foreign trust domain by naming its bundle endpoint and the
profile that authenticates it, optionally with the domain's current bundle to
bootstrap trust.
