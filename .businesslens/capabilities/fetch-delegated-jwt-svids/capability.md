---
availability:
  - place: delegated-identity-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Delegated Identity API
---

# Fetch delegated JWT-SVIDs

An authorized delegate receives JWT-SVIDs for the audiences it names on behalf
of a process it identifies by selectors or process ID.
