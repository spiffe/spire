# Server plugin: NodeAttestor "http_challenge"

*Must be used in conjunction with the [agent-side http_challenge plugin](plugin_agent_nodeattestor_http_challenge.md)*

The `http_challenge` plugin handshakes via http to ensure the agent is running on a valid
dns name.

The SPIFFE ID produced by the plugin is based on the dns name attested.
The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/http_challenge/<hostname>
```

| Configuration           | Description                                                                                                                                               | Default                             |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| `allowed_dns_patterns`  | A list of regular expressions to match to the hostname being attested. If none match, attestation will fail. If unset, all hostnames are allowed.         |                                     |
| `required_port`         | Set to a port number to require clients to listen only on that port. If unset, all port numbers are allowed                                               |                                     |
| `allow_non_root_ports`  | Set to true to allow ports >= 1024 to be used by the agents with the advertised_port                                                                      | true                                |
| `tofu`                  | Trust on first use of the successful challenge. Can only be disabled if allow_non_root_ports=false or required_port < 1024                                | true                                |

A sample configuration:

```hcl
    NodeAttestor "http_challenge" {
        plugin_data {
            # Only match hosts that start with p, have a number, then end in example.com. Ex: 'p1.example.com'
            allowed_dns_patterns = ["p[0-9]\.example\.com"]

            # Only allow clients to use port 80
            required_port = 80

            # Change the agent's SPIFFE ID format
            # agent_path_template = "/spire/agent/http_challenge/{{ .Hostname }}"
        }
    }
```

## Selectors

| Selector | Example                                  | Description            |
|----------|------------------------------------------|------------------------|
| Hostname | `http_challenge:hostname:p1.example.com` | The Subject's Hostname |

## Security Considerations

Generally, TCP ports are accessible to any user of the node. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

The `http_challenge` node attestor implements multiple features to mitigate the risk.

Trust On First Use (or TOFU) is one such option. For any given node, attestation may occur only once when enabled. Subsequent attestation attempts will be rejected.

With TOFU, it is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.

You also can require the port to be a trusted port that only trusted user such as root can open (port number < 1024).
