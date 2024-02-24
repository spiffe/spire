# Agent plugin: NodeAttestor "httppop"

*Must be used in conjunction with the server-side httppop plugin*

The `httppop` plugin handshakes via http to ensure the agent is running on a valid
dns name.

The SPIFFE ID produced by the server-side `httppop` plugin is based on the dns name of the agent.
The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/httppop/<hostname>
```

| Configuration     | Description                                                                                                                                      | Default   |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| `hostname`        | Hostname to use for handshaking. If unset, it will be automatically detected.                                                                    |           |
| `agentname`       | Name of this agent on the host. Useful if you have multilpe agents bound to different spire servers on the same host.                            | "default" |
| `port`            | The port to listen on.                                                                                                                           | 80        |
| `advertised_port` | The port to tell the server to call back on. If overridden, must be used in conjunction with the server plugins `allow_alternate_ports` setting. | 80        |

If `advertised_port` != `port`, you will need to setup an http proxy between the two ports. This is useful if you already run a webserver on port 80.

A sample configuration:

```hcl
    NodeAttestor "httppop" {
        plugin_data {
            port = 80
        }
    }
```

## Proxies

Normally validation is done via port 80. If you already have a webserver on port 80 or want to use multilple agents with different SPIRE servers, you can have your webserver proxy over
to the SPIRE agent(s) by setting up a proxy on `/.well-known/spiffe/nodeattestor/httppop/$agentname` to `http://localhost:$port/.well-known/spiffe/nodeattestor/httppop/$agentname`.

Example spire agent configuration:

```hcl
    NodeAttestor "httppop" {
        plugin_data {
            port = 8080
        }
    }
```
