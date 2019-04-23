# Server plugin: NodeAttestor "sshpop"

*Must be used in conjunction with the agent-side sshpop plugin*

The `sshpop` plugin attests nodes that have been provisioned with an ssh
identity through an out-of-band mechanism. It verifies that the certificate is
rooted to a trusted set of CAs and issues a signature based proof-of-possession
challenge to the agent plugin to verify that the node is in possession of the
private key.

The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
which is an unpadded base64 encoded sha256 hash of the certificate in openssh format.

```
spiffe://<trust-domain>/spire/agent/sshpop/<fingerprint>
```

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `cert_authorities` | A list of trusted CAs in ssh `authorized_keys` format. | |
