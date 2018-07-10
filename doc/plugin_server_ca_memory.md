# Server plugin: ServerCA "memory"

The `memory` plugin implements an in-memory signing authority. The signing
keypair is optionally persisted to disk. When the server is loaded, if no
keypair has been persisted, or if the keypair is expiring/expired, a new
keypair is generated against the upstream CA.

| Configuration | Description                                            |
| ------------- | -------------------------------------------------------|
| trust_domain  | The trust domain to issue SVIDs in                     |
| cert_subject  | A certificate subject                                  |
| keypair_path  | Path on disk to persist the signing keypair (optional) |

Example of `certSubject` configuration:
```
certSubject = {
    Country = ["US"],
    Organization = ["SPIFFE"],
    CommonName = "",
  }
```
