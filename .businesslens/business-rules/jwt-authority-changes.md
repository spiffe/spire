---
appliesTo:
  - type: entity
    id: jwt-authority
    effect: changes
permits:
  - actors:
      - operator
      - admin-workload
    when:
      - entity: server-configuration
        fact: JWT-SVIDs disabled
        is: false
  - unattended: true
    when:
      - entity: server-configuration
        fact: JWT-SVIDs disabled
        is: false
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: disable_jwt_svids
---

# JWT authorities are activated and tainted by operators, admin workloads and the rotation schedule only while JWT-SVIDs are enabled

With `disable_jwt_svids` set the server generates no JWT keys and refuses
every JWT authority call as "JWT functionality is disabled".
