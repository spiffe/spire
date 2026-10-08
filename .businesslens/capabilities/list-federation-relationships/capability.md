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
    target: cmd/spire-server/cli/federation/list.go
---

# List federation relationships

List the dynamic federation relationships, or show one by trust domain. Static
relationships from the configuration file are not listed.
