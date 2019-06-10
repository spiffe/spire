# Server plugin: NodeAttestor "sshpop"

*Must be used in conjunction with the agent-side sshpop plugin*

The `sshpop` plugin attests nodes that have been provisioned with an ssh
identity through an out-of-band mechanism. It verifies that the certificate is
rooted to a trusted set of CAs and issues a signature based proof-of-possession
challenge to the agent plugin to verify that the node is in possession of the
private key.

The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
which is an unpadded url-safe base64 encoded sha256 hash of the certificate in openssh format.

```
spiffe://<trust-domain>/spire/agent/sshpop/<fingerprint>
```

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `cert_authorities` | A list of trusted CAs in ssh `authorized_keys` format. | |
| `cert_authorities_path` | A file that contains a list of trusted CAs in ssh `authorized_keys` format. | |

If both `cert_authorities` and `cert_authorities_path` are configured, the resulting set of authorized keys is the union of both sets.

### Example Config

##### agent.conf

```
    NodeAttestor "sshpop" {
        plugin_data {
            host_cert_path = "./conf/agent/dummy_agent_ssh_key-cert.pub"
            host_key_path = "./conf/agent/dummy_agent_ssh_key"
        }
    }
```

##### server.conf

```
    NodeAttestor "sshpop" {
        plugin_data {
            cert_authorities = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAWPAsKJ/qMYUIBeH7BLMRCE/bkUvMHX+7OZhANk45S"]
            cert_authorities_path = "./conf/server/dummy_ssh_cert_authority.pub"
        }
    }
```
