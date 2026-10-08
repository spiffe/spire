---
appliesTo:
  - type: context
    context:
      place: "server-api::agents"
references:
  - kind: code
    role: implementation
    target: "pkg/server/endpoints/middleware.go#AgentAuthorizer"
---

# Agent calls require a current, unbanned agent SVID

The server accepts an agent call only when the caller's SVID has not expired
and its serial is the accepted or pending one of an attested, unbanned agent;
otherwise it tells the agent whether it is banned, expired, not attested or
holding a replaced SVID.
