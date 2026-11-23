# Server plugin: BundlePublisher "k8s_clustertrustbundle"

The `k8s_clustertrustbundle` plugin puts the X.509 authorities of the current trust bundle of the server in a designated Kubernetes [ClusterTrustBundle](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles), keeping it updated. The plugin supports configuring multiple clusters.

ClusterTrustBundles are cluster-scoped and readable by any authenticated user, so workloads that are not SPIRE-aware can mount the trust bundle with a `clusterTrustBundle` projected volume.

The plugin uses the `certificates.k8s.io/v1` API, available since Kubernetes 1.37. On a cluster that does not serve it, the plugin falls back to `certificates.k8s.io/v1beta1`, which Kubernetes 1.33 to 1.36 serve once the `ClusterTrustBundle` feature gate and the `certificates.k8s.io/v1beta1/clustertrustbundles` API are enabled on the API server.

The plugin accepts the following configuration:

| Configuration | Description                                                                                       | Default |
|---------------|---------------------------------------------------------------------------------------------------|---------|
| `clusters`    | A map of clusters, keyed by an arbitrary ID, where the plugin publishes the current trust bundle. |         |

> [!WARNING]
> When `clusters` is empty, the plugin does not publish the bundle.

Each cluster in the main configuration has the following configuration options:

| Configuration             | Description                                                                                                                                                                                                        | Required | Default |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| cluster_trust_bundle_name | The name of the ClusterTrustBundle. When `signer_name` is set, the name must start with the signer name, with slashes replaced by colons, followed by a colon (e.g. `example.org:spire:` for `example.org/spire`). | Yes.     |         |
| signer_name               | The signer name set on the ClusterTrustBundle. Kubernetes does not allow changing the signer name of an existing ClusterTrustBundle.                                                                               | No.      |         |
| kubeconfig_path           | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, in-cluster credentials will be used.                                                   | No.      |         |

The trust bundle is always stored in PEM format, and only the X.509 authorities are included. A bundle without X.509 authorities is not published.

## Configuring Kubernetes

To use this plugin, configure Kubernetes permissions for the SPIRE Server's Service Account:

- For in-cluster SPIRE servers: grant permissions to the Service Account running SPIRE.
- For out-of-cluster SPIRE servers: grant permissions to the Service Account specified in the kubeconfig.

The plugin uses the Kubernetes Apply operation to manage ClusterTrustBundles. This operation will create the ClusterTrustBundle if it doesn't exist, or update it if it does. Since ClusterTrustBundles are cluster-scoped, the permissions must be granted with a ClusterRole.

### Required Permissions

The Service Account needs the following permissions:

- `patch` on ClusterTrustBundles (required for the Apply operation to update resources)
- `create` on ClusterTrustBundles (required if the ClusterTrustBundle doesn't exist)
- `attest` on the `signers` resource of the `certificates.k8s.io` API group for the configured signer name (required only when `signer_name` is set)

### Example

In this example, assume that Service Account is `spire-server` and the signer name is `example.org/spire`.

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-clustertrustbundle
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["clustertrustbundles"]
  verbs: ["create", "patch"]
  resourceNames: ["example.org:spire:bundle"]  # Restrict to specific ClusterTrustBundle for create and patch operations
- apiGroups: ["certificates.k8s.io"]
  resources: ["signers"]
  verbs: ["attest"]
  resourceNames: ["example.org/spire"]  # Only needed when signer_name is set

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-clustertrustbundle
subjects:
- kind: ServiceAccount
  name: spire-server
  namespace: spire
roleRef:
  kind: ClusterRole
  name: spire-server-clustertrustbundle
  apiGroup: rbac.authorization.k8s.io
```

> [!NOTE]
> The Apply operation uses Server-Side Apply (SSA) with a field manager name of `spire-bundlepublisher-k8s_clustertrustbundle`.

## Consuming the trust bundle

A Pod can mount the trust bundle with a `clusterTrustBundle` projected volume, selecting the ClusterTrustBundle either by name or by signer name:

```yaml
  volumes:
  - name: spire-bundle
    projected:
      sources:
      - clusterTrustBundle:
          name: example.org:spire:bundle
          path: bundle.pem
      # Or, to merge all the ClusterTrustBundles of a signer:
      # - clusterTrustBundle:
      #     signerName: example.org/spire
      #     labelSelector: {}
      #     path: bundle.pem
```

## Sample configuration

The following configuration keeps the local trust bundle updated in ClusterTrustBundles from two different clusters.

```hcl
    BundlePublisher "k8s_clustertrustbundle" {
        plugin_data {
            clusters = {
                "example-cluster-1" = {
                    cluster_trust_bundle_name = "example.org:spire:bundle"
                    signer_name = "example.org/spire"
                    kubeconfig_path = "/file/path/cluster-1"
                },
                "example-cluster-2" = {
                    cluster_trust_bundle_name = "example.org"
                    kubeconfig_path = "/file/path/cluster-2"
                }
            }
        }
    }
```
