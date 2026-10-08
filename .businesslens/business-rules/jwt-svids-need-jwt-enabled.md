---
appliesTo:
  - type: entity
    id: jwt-svid
    effect: creates
permits:
  - actors:
      - operator
      - admin-workload
      - agent
      - workload
      - authorized-delegate
      - broker
    when:
      - entity: server-configuration
        fact: JWT-SVIDs disabled
        is: false
references:
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: disable_jwt_svids
  - kind: code
    role: implementation
    target: pkg/server/api/svid/v1/service.go
---

# JWT-SVIDs are issued only while the server has JWT-SVIDs enabled

With `disable_jwt_svids` set the server signs no JWT-SVIDs: minting and agent
requests are refused as "JWT functionality is disabled", so no workload,
delegate or broker receives one.
