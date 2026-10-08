---
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/agent/v1/service.go#CreateJoinToken"
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/token/generate.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server token generate
---

# Generate a join token

Issue a single-use join token an agent can attest its node with, optionally
giving the node an extra SPIFFE ID through a registration entry.
