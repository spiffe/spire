---
appliesTo:
  - type: capability
    id: create-federated-bundle
  - type: capability
    id: set-federated-bundle
  - type: capability
    id: edit-federated-bundle
  - type: capability
    id: delete-federated-bundle
  - type: capability
    id: list-federated-bundles
references:
  - kind: code
    role: implementation
    target: pkg/server/api/bundle/v1/service.go
---

# The server's own bundle is never created, set, edited, deleted or fetched as a federated bundle

Federated bundle operations refuse the server's own trust domain; its own
bundle changes only through its authorities, appended authorities and
downstream servers.
