---
type: api
actors:
  - authorized-delegate
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/api/endpoints.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Delegated Identity API
---

# Delegated Identity API

The API the agent serves on its Agent Admin API socket, separate from the
Workload API, through which an authorized delegate obtains identities and
bundles for processes it vouches for. It is available only while the agent's
admin socket is configured.
