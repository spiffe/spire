---
domain: registration-entries
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/entry/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server entry
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/entry/show.go
---

# Show registration entries

List registration entries, or show one by its Entry ID, filtered by SPIFFE ID,
parent ID, selectors, federated trust domains, hint or the downstream flag.
