---
domain: agents
availability:
  - place: "server-api::bootstrap"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/agent/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server agent
  - kind: code
    role: implementation
    target: pkg/server/plugin/nodeattestor/base/base.go
  - kind: code
    role: implementation
    target: pkg/agent/attestor/node/node.go
---

# Attest an agent

Admit an agent by verifying evidence about its node through a configured node
attestor, such as a cloud instance identity document, a Kubernetes projected
service account token, an X.509 or TPM proof of possession, or a join token.
The server records the agent and signs its agent SVID.
