# Agent plugin: NodeAttestor "http_challenge"

*Must be used in conjunction with the server-side http_challenge plugin*

The `http_challenge` plugin handshakes via http to ensure the agent is running on a valid
dns name.

The SPIFFE ID produced by the server-side `http_challenge` plugin is based on the dns name of the agent.
The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/http_challenge/<hostname>
```

| Configuration     | Description                                                                                                                                      | Default   |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| `hostname`        | Hostname to use for handshaking. If unset, it will be automatically detected.                                                                    |           |
| `agentname`       | Name of this agent on the host. Useful if you have multiple agents bound to different spire servers on the same host and sharing the same port.  | "default" |
| `port`            | The port to listen on. If unspecified, a random value will be used.                                                                              | random    |
| `advertised_port` | The port to tell the server to call back on.                                                                                                     | $port     |

If `advertised_port` != `port`, you will need to setup an http proxy between the two ports. This is useful if you already run a webserver on port 80.

A sample configuration:

```hcl
    NodeAttestor "http_challenge" {
        plugin_data {
            port = 80
        }
    }
```

## Proxies

Say you want to validate using port 80 to be internet firewall friendly. If you already have a webserver on port 80 or want to use multiple agents with different SPIRE servers and use the same port,
you can have your webserver proxy over to the SPIRE agent(s) by setting up a proxy on `/.well-known/spiffe/nodeattestor/http_challenge/$agentname` to
`http://localhost:$port/.well-known/spiffe/nodeattestor/http_challenge/$agentname`.

Example spire agent configuration:

```hcl
    NodeAttestor "http_challenge" {
        plugin_data {
            port = 8080
            advertised_port = 80
        }
    }
```
