---
kind: system
acts: internal
references:
  - kind: code
    role: implementation
    target: pkg/server/api/agent/v1/service.go
  - kind: code
    role: implementation
    target: "pkg/server/endpoints/middleware.go#AgentAuthorizer"
---

# Agent

A SPIRE Agent that has attested the node it runs on to the SPIRE Server and
holds an agent SVID. The server keeps a record of every attested agent, which
its documentation calls an attested node; the agent in turn serves the
workloads on its node.

## Information kept

- **SPIFFE ID** — the agent's identity, derived from its attestation evidence or join token
- **Attestation type** — the node attestor that admitted it, such as join_token, x509pop or k8s_psat
- **Node selectors** — what attestation established about the node
- **Serial number** — the serial of the agent SVID the server accepts; empty once the agent is banned
- **Expiration time** — when that agent SVID expires
- **Pending SVID** — the serial and expiry of a renewed agent SVID, accepted in place of the current one the first time the agent uses it
- **Can re-attest** — whether its attestation method lets it attest again instead of renewing
- **Agent version** — the SPIRE version the agent last reported

## States

### Attested

The agent holds an accepted SVID and may sync entries and have SVIDs signed
for its node.

### Banned

The server refuses every request from the agent and every attempt to attest it
again, until its record is evicted.
