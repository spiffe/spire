---
kind: system
acts: external
references:
  - kind: doc
    role: context
    target: doc/scaling_spire.md
    title: Nested SPIRE
  - kind: code
    role: implementation
    target: pkg/server/plugin/upstreamauthority/spire/spire_server_client.go
---

# Downstream server

A SPIRE Server nested below this one. It authenticates with an X.509-SVID
whose SPIFFE ID a registration entry marks Downstream, obtains its signing CA
from this server, and publishes its JWT signing keys into this server's
bundle.
