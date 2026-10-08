---
appliesTo:
  - type: entity
    id: x509-authority
    effect: removes
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
    target: "pkg/server/api/localauthority/v1/service.go#RevokeX509Authority"
---

# Local X.509 authorities are revoked only by operators and admin workloads while no upstream authority is configured

With an upstream authority configured, the upstream authority is revoked
instead of the local X.509 authorities it signed.
