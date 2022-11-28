# Agent plugin: NodeAttestor "sshpop"

*Must be used in conjunction with the server-side sshpop plugin*

The `sshpop` plugin provides attestation data for a node that has been
provisioned with an ssh identity through an out-of-band mechanism and responds
to a signature based proof-of-possession challenge issued by the server
plugin.

The SPIFFE ID produced by the server-side `sshpop` plugin is based on the certificate fingerprint,
which is an unpadded url-safe base64 encoded sha256 hash of the certificate in openssh format.

```xml
spiffe://<trust_domain>/spire/agent/sshpop/<fingerprint>
```

| Configuration    | Description                                            | Default                                |
|------------------|--------------------------------------------------------|----------------------------------------|
| `host_key_path`  | The path to the private key on disk in openssh format. | `"/etc/ssh/ssh_host_rsa_key"`          |
| `host_cert_path` | The path to the certificate on disk in openssh format. | `"/etc/ssh/ssh_host_rsa_key-cert.pub"` |

A sample configuration:

```hcl
    NodeAttestor "sshpop" {
        plugin_data {
            host_cert_path = "./conf/agent/dummy_agent_ssh_key-cert.pub"
            host_key_path = "./conf/agent/dummy_agent_ssh_key"
        }
    }
```
