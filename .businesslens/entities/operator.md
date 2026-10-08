---
kind: person
acts: external
references:
  - kind: code
    role: implementation
    target: pkg/server/api/middleware/caller.go
  - kind: doc
    role: context
    target: doc/spire_server.md
---

# Operator

A person who runs and administers a SPIRE deployment from the hosts its
servers and agents run on, using the server and agent command lines. Any
caller on the SPIRE Server's local API socket acts with the Operator's
authority.
