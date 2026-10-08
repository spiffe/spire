---
availability:
  - place: "server-api::agents"
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/entry/v1/service.go#SyncAuthorizedEntries"
  - kind: code
    role: implementation
    target: pkg/server/authorizedentries/cache.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/sync.go
---

# Sync authorized entries

Every few seconds an agent obtains the registration entries it is authorized
for that changed since its last sync, so it can serve and rotate the
identities of its node.
