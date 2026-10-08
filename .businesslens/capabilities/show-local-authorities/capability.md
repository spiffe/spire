---
domain: local-authority
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
---

# Show local authorities

Show the server's active, prepared and old X.509 or JWT authorities.
