# Server plugin: UpstreamAuthority "spire"

The `spire` plugin uses credentials fetched from the Workload API to call an upstream SPIRE server in the same trust domain, requesting an intermediate signing certificate to use as the server's X.509 signing authority.

The SVIDs minted in a nested configuration are valid in the entire trust domain, not only in the scope of the server that originated the SVID.

In the case of X509-SVID, this is easily achieved because of the chaining semantics that X.509 has. On the other hand, for JWT-SVID, this capability is accomplished by propagating every JWT-SVID public signing key to the whole topology.

The plugin accepts the following configuration options:

| Configuration       | Description                                                                  |
|---------------------|------------------------------------------------------------------------------|
| server_address      | IP address or DNS name of the upstream SPIRE server in the same trust domain |
| server_port         | Port number of the upstream SPIRE server in the same trust domain            |
| workload_api_socket | Path to the Workload API socket (Unix only; e.g. the SPIRE Agent API socket) |
| experimental        | The experimental options that are subject to change or removal               |

These are the current experimental configurations:

| experimental                 | Description                                                                                               | Default |
|------------------------------|-----------------------------------------------------------------------------------------------------------|---------|
| workload_api_named_pipe_name | Pipe name of the Workload API named pipe (Windows only; e.g. pipe name of the SPIRE Agent API named pipe) |         |
| require_pq_kem               | Require use of a post-quantum-safe key exchange method for TLS handshakes                                 | false   |

Sample configuration (Unix):

```hcl
    UpstreamAuthority "spire" {
        plugin_data {
            server_address = "upstream-spire-server",
            server_port = "8081",
            workload_api_socket = "/tmp/spire-agent/public/api.sock"
        }
    }
```

Sample configuration (Windows):

```hcl
    UpstreamAuthority "spire" {
        plugin_data {
            server_address = "upstream-spire-server",
            server_port = "8081",
            experimental {
                workload_api_named_pipe_name = "\\spire-agent\\public\\api"
            }
        }
    }
```
