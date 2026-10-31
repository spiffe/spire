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
| refresh_hint    | Sets the refresh hint for the bundle when using the spiffe format. Specified as string e.g. '10m', '1h'. See [time.ParseDuration](https://pkg.go.dev/time#ParseDuration) for details                   | No.      |         |
| oidc_compatible | When `true`, the `jwks` format is the JWK Set served by the OIDC Discovery Provider: only the JWT authorities, each with its `alg` and `use`. See [JWKS format](#jwks-format).                         | No.      | false   |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

When `oidc_compatible` is `true`, the JWK Set only includes the JWT authorities, so that it can be used by OIDC relying parties to verify JWT-SVIDs. It has the same keys, with the same members, as the document served on the keys endpoint of the [OIDC Discovery Provider](../support/oidc-discovery-provider/README.md) with `set_key_use` enabled: the X.509 authorities are left out, and every key has its `kid`, its `use` parameter set to `sig` and its `alg` parameter (`RS256` for RSA keys of 2048 bits or more, `ES256` for P-256 keys and `ES384` for P-384 keys). When the bundle has no JWT authorities, an empty set (`{"keys":[]}`) is published, whereas the provider serves no document. A key with no algorithm in that list, such as an RSA key under 2048 bits, is published without `alg`, as the provider does, and a warning is logged. Publishing fails if the key of a JWT authority cannot be parsed. This option can only be used with the `jwks` format.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Configuring Kubernetes

To use this plugin, configure Kubernetes permissions for the SPIRE Server's Service Account:

- For in-cluster SPIRE servers: grant permissions to the Service Account running SPIRE.
- For out-of-cluster SPIRE servers: grant permissions to the Service Account specified in the kubeconfig.

The plugin uses the Kubernetes Apply operation to manage ConfigMaps. This operation will create the ConfigMap if it doesn't exist, or update it if it does. The Service Account needs permission to use the `patch` verb on ConfigMaps in the specified namespace.

### Required Permissions

The Service Account needs the following permissions:

- `get` on ConfigMaps (required for the Apply operation to read the current state)
- `patch` on ConfigMaps (required for the Apply operation to update resources)
- `create` on ConfigMaps (required if the ConfigMap doesn't exist)

### Example

In this example, assume that Service Account is `spire-server`.

```yaml
kind: Role # Note: Using Role instead of ClusterRole for namespace-scoped permissions
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-role
  namespace: spire
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["create", "get", "patch"]
  resourceNames: ["spire-bundle"]  # Restrict to specific ConfigMap for create, get and patch operations

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

> [!NOTE]
> The Apply operation uses Server-Side Apply (SSA) with a field manager name of `spire-bundlepublisher-k8s_configmap`. This ensures that SPIRE's updates to the ConfigMap are tracked and can coexist with other controllers that might be managing different fields of the same ConfigMap.

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
