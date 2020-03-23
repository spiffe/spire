# Server plugin: UpstreamAuthority "spire"

The `spire` plugin uses credentials fetched from the Workload API to call an upstream SPIRE server in the same trust domain, requesting an intermediate signing certificate to use as the server's X.509 signing authority.

The SVIDs minted in a nested configuration are valid in the entire trust domain, not only in the scope of the server that originated the SVID.

In the case of X509-SVID, this is easily achieved because of the chaining semantics that X.509 has. On the other hand, for JWT-SVID, this capability is accomplished by propagating every JWT-SVID public signing key to the whole topology.

The plugin accepts the following configuration options:

| Configuration           | Description                                                                  |
| ----------------------- | ---------------------------------------------------------------------------- |
| server_address          | IP address or DNS name of the upstream SPIRE server in the same trust domain |
| server_port             | Port number of the upstream SPIRE server in the same trust domain            |
| workload_api_socket     | Path to the workload API socket                                              |

A sample configuration:

```
    UpstreamAuthority "spire" {
        plugin_data {
            server_address = "upstream-spire-server",
            server_port = "8081",
            workload_api_socket = "/tmp/agent.sock"
        }
    }
```
