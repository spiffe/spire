---
kind: system
acts: external
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: admin_ids and entry -admin
---

# Admin workload

Software that administers SPIRE remotely through the Server API, such as a
controller that keeps registration entries in step with a cluster. It
authenticates with an X.509-SVID whose SPIFFE ID is either listed in the
server's `admin_ids` or carried by a registration entry marked Admin.
