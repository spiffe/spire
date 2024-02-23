# Agent plugin: NodeAttestor "http"

*Must be used in conjunction with the server-side http plugin*

The `http` plugin handshakes via http to ensure the agent is running on a valid
dns name.

The SPIFFE ID produced by the server-side `http` plugin is based on the dns name of the agent.
The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/http/<hostname>
```

| Configuration     | Description                                                                                                                                      | Default |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `hostname`        | Hostname to use for handshaking. If unset, it will be automatically detected.                                                                    |         |
| `port`            | The port to listen on.                                                                                                                           | 80      |
| `advertised_port` | The port to tell the server to call back on. If overridden, must be used in conjunction with the server plugins `allow_alternate_ports` setting. | 80      |

If `advertised_port` != `port`, you will need to setup an http proxy between the two ports. This is useful if you already run a webserver on port 80.

A sample configuration:

```hcl
    NodeAttestor "http" {
        plugin_data {
            port = 80
        }
    }
```
