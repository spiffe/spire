---
appliesTo:
  - type: entity
    id: x509-authority
    effect: changes
    to: Tainted
permits:
  - actors:
      - operator
      - admin-workload
    when:
      - entity: server-configuration
        fact: Upstream authority
        absent: true
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/localauthority/v1/service.go#TaintX509Authority"
---

# Local X.509 authorities are tainted only while no upstream authority is configured

With an upstream authority configured, the upstream authority is tainted
instead of the local X.509 authorities it signed.
