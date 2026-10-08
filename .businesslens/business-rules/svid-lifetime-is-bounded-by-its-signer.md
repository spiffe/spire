---
appliesTo:
  - type: capability
    id: mint-svid
  - type: capability
    id: issue-svid
  - type: capability
    id: request-downstream-x509-ca
references:
  - kind: code
    role: implementation
    target: pkg/server/credtemplate/builder.go
---

# No SVID or downstream CA outlives the authority that signed it

A requested lifetime of zero falls back to the server's default, and every
X.509-SVID, JWT-SVID and downstream CA expires no later than the authority
that signed it.
