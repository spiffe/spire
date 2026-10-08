---
appliesTo:
  - type: capability
    id: refresh-bundle
  - type: capability
    id: list-federation-relationships
  - type: capability
    id: delete-federation-relationship
references:
  - kind: code
    role: implementation
    target: pkg/server/bundle/client/sources.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Federation configuration
---

# Federation configured in the server's configuration file takes precedence

For a trust domain configured in the server's configuration file, that static
relationship decides where and how its bundle is fetched, whatever dynamic
relationship the API holds for it; static relationships are not listed and not
deleted through the API.
