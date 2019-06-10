# Server plugin: UpstreamCA "spire"

The `spire` plugin loads root CA credentials from upstream SPIRE server in the same trust domain, using
them to generate intermediate signing certificates for the server's signing authority.

The plugin accepts the following configuration options:

| Configuration           | Description                                                                  |
| ----------------------- | ---------------------------------------------------------------------------- |
| server_address          | IP address or DNS name of the upstream SPIRE server in the same trust domain |
| server_port             | Port number of the upstream SPIRE server in the same trust domain            |
| workload_api_socket     | Path to the workload API socket                                              |

A sample configuration:

```
    UpstreamCA "spire" {
        plugin_data {
            server_address = "upstream-spire-server",
            server_port = "8081",
            workload_api_socket = "/tmp/agent.sock"
        }
    }
```
