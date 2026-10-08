---
appliesTo:
  - type: capability
    id: create-registration-entry
  - type: capability
    id: edit-registration-entry
references:
  - kind: code
    role: implementation
    target: pkg/server/api/entry.go
  - kind: code
    role: implementation
    target: pkg/server/datastore/sqlstore/sqlstore.go
---

# A registration entry names valid identities in the server's trust domain

A registration entry's SPIFFE ID and parent ID are in the server's trust
domain, it has at least one selector, its DNS names are valid, its hint is at
most 1024 characters, it federates only with trust domains the server holds a
bundle for, and an entry that stores its SVIDs has selectors of one type only.
