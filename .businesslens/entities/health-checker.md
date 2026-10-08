---
kind: system
acts: external
references:
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Health check configuration
---

# Health checker

A system that probes the liveness and readiness of a SPIRE Server, SPIRE Agent
or OIDC Discovery Provider over HTTP, such as a container orchestrator.
