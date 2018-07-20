# Server plugin: NodeAttestor "k8s"

*Must be used in conjunction with the agent-side k8s plugin*

The `k8s` plugin attests nodes that have a valid certificate issued
by a Kubernetes Certificate Authority. It verifies that the certificate
is signed by a trusted CA and that the agent plugin has access to
the corresponding private key using a signature-based challenge.

The SPIFFE ID produced by the plugin is based on the common name of the certificate
and is in the form:

```
spiffe://<trust domain>/spire/agent/k8s/system/node/<host name>
```


| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `trust_domain`  |  The trust domain that the node belongs to. |  |
| `ca_bundle_path` | The path to the trusted CA bundle on disk. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. | |
