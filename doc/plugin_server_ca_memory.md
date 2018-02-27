# Server plugin: ControlPlaneCA "memory"

The `memory` plugin implements an in-memory signing authority. No keys are persisted to disk, and
if the server is restarted, a new signing authority is generated against the upstream CA.

| Configuration | Description                                    |
| ------------- | ---------------------------------------------- |
| trust_domain  | The trust domain to issue SVIDs in             |
| key_size      | The size of keys to generate, defaults to 2048 |
| cert_subject  | A certificate subject                          |

Example of `certSubject` configuration:
```
certSubject = {
    Country = ["US"],
    Organization = ["SPIFFE"],
    CommonName = "",
  }
```
