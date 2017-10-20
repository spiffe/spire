# Server plugin: ca-memory

The `ca-memory` plugin is responsible for processing CSR requests from Agents if the Server is
configured to carry an intermediate signing certificate. This plugin is also responsible for
generating the CSR necessary for an intermediate signing cert, as well as storing the key in memory
or hardware.

| Configuration | Description                                    |
| ------------- | ---------------------------------------------- |
| trustDomain   | The trust domain to issue SVIDs in             |
| keySize       | The size of keys to generate, defaults to 2048 |
| certSubject   | A certificate subject                          |

Example of `certSubject` configuration:
```
certSubject = {
    Country = ["US"],
    Organization = ["SPIFFE"],
    CommonName = "",
  }
```
