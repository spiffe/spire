# Server plugin: BundlePublisher "k8s_configmap"

The `k8s_configmap` plugin puts the current trust bundle of the server in a designated
Kubernetes ConfigMap, keeping it updated. The plugin supports configuring multiple clusters.

The plugin accepts the following configuration options:

| Configuration   | Description                                                                                                                                                                                            | Required                                    | Default |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|---------|
| configmap_name  | The name of the ConfigMap.                                                                                                                                                                             | Yes.                                        |         |
| configmap_key   | The key within the ConfigMap for the bundle.                                                                                                                                                           | Yes.                                        |         |
| namespace       | The namespace containing the ConfigMap.                                                                                                                                                                | Yes.                                        |         |
| kubeconfig_path | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, in-cluster credentials will be used. Only one in-cluster can be configured.| Required when configuring a remote cluster. |         |
| format          | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details.                                         | Yes.                                        |         |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Sample configuration

The following configuration keeps the local trust bundle updated in ConfigMaps from two different clusters.

```hcl
    BundlePublisher "k8s_configmap" {
        plugin_data {
            clusters = [
                {
                    format = "spiffe"
                    namespace = "spire"
                    configmap_name = "example.org"
                    configmap_key = "trust-bundle"
                    kubeconfig_path = "/file/path/cluster-1"
                },
                {
                    format = "pem"
                    namespace = "spire"
                    configmap_name = "example.org2"
                    configmap_key = "trust-bundle"
                    kubeconfig_path = "/file/path/cluster-2"
                }
            ]
        }
    }
```
