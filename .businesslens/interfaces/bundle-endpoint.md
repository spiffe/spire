---
type: api
actors:
  - federated-server
references:
  - kind: code
    role: implementation
    target: pkg/server/endpoints/bundle/server.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Federation configuration
---

# SPIFFE bundle endpoint

The HTTPS SPIFFE bundle endpoint a SPIRE Server serves when configured to, so
other trust domains can federate with it. It authenticates itself with Web
PKI, using a certificate from ACME or from disk, or with the server's own
X.509-SVID, and does not authenticate its callers.
