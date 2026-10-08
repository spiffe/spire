---
type: cli
actors:
  - operator
references:
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/cli.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Command line options
---

# SPIRE Server command line

The `spire-server` command line an Operator runs on a SPIRE Server host. It
administers registration entries, agents, join tokens, bundles, federation
relationships and the server's authorities, mints SVIDs, and checks, validates
and debugs the server, all through the server's local API socket.
