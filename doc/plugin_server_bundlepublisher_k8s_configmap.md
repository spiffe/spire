# Server plugin: BundlePublisher "k8s_configmap"

The `k8s_configmap` plugin puts the current trust bundle of the server in a designated
Kubernetes ConfigMap, keeping it updated. The plugin supports configuring multiple clusters.

The plugin accepts the following configuration:

| Configuration | Description                                                                                       | Default |
|---------------|---------------------------------------------------------------------------------------------------|---------|
| `clusters`    | A map of clusters, keyed by an arbitrary ID, where the plugin publishes the current trust bundle. |         |

> [!WARNING]
> When `clusters` is empty, the plugin does not publish the bundle.

Each cluster in the main configuration has the following configuration options:

| Configuration   | Description                                                                                                                                                                                            | Required | Default |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| configmap_name  | The name of the ConfigMap.                                                                                                                                                                             | Yes.     |         |
| configmap_key   | The key within the ConfigMap for the bundle.                                                                                                                                                           | Yes.     |         |
| namespace       | The namespace containing the ConfigMap.                                                                                                                                                                | Yes.     |         |
| kubeconfig_path | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, in-cluster credentials will be used.                                       | No.      |         |
| format          | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details.                                         | Yes.     |         |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Configuring Kubernetes

To use this plugin, configure Kubernetes permissions for the SPIRE Server's Service Account:

- For in-cluster SPIRE servers: grant permissions to the Service Account running SPIRE.
- For out-of-cluster SPIRE servers: grant permissions to the Service Account specified in the kubeconfig.

The Service Account needs permission to:

- `get` and `update` the specific ConfigMap (required).
- `create` ConfigMaps in the namespace (optional, only if the ConfigMap doesn't exist).

### Example

In this example, assume that Service Account is `spire-server`.

```yaml
kind: Role  # Note: Using Role instead of ClusterRole for namespace-scoped permissions
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-role
  namespace: spire
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "update"]
  resourceNames: ["spire-bundle"]  # Can only update this specific ConfigMap
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["create"]  # Can create any ConfigMap in the namespace if needed

---

kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-role-binding
  namespace: spire
subjects:
- kind: ServiceAccount
  name: spire-server
  namespace: spire
roleRef:
  kind: Role
  name: spire-server-role
  apiGroup: rbac.authorization.k8s.io

---

apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-bundle
  namespace: spire
```

## Sample configuration

The following configuration keeps the local trust bundle updated in ConfigMaps from two different clusters.

```hcl
    BundlePublisher "k8s_configmap" {
        plugin_data {
            clusters = {
                "example-cluster-1" = {
                    configmap_name = "example.org"
                    configmap_key = "bundle"
                    namespace = "spire"
                    kubeconfig_path = "/file/path/cluster-1"
                    format = "spiffe"
                },
                "example-cluster-2" = {
                    configmap_name = "example.org"
                    configmap_key = "bundle"
                    namespace = "spire"
                    kubeconfig_path = "/file/path/cluster-2"
                    format = "pem"
                }
            }
        }
    }
```
