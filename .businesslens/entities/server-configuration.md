---
singleton: true
references:
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/run/run.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Server configuration file
---

# Server configuration

The settings of a SPIRE Server, read from its configuration file when it
starts and never changed through its APIs. Only the settings that decide
whether a Capability is available are kept here.

## Information kept

- **JWT-SVIDs disabled** — whether `disable_jwt_svids` turns off JWT keys, JWT-SVID signing and every JWT-related API call
- **Upstream authority** — the upstream authority plugin the server is configured with, if any
