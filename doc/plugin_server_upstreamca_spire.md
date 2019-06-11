# Server plugin: UpstreamCA "spire"

The `spire` plugin uses credentials fetched from the Workload API to call an upstream SPIRE server in the same trust domain, requesting an intermediate signing certificate to use as the server's X.509 signing authority.

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
