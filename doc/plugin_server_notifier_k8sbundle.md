# Server plugin: Notifier "k8sbundle"

The `k8sbundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to a Kubernetes
ConfigMap, and optionally Webhooks and APIServices.

The certificates in the ConfigMap can be used to bootstrap SPIRE agents.

The plugin accepts the following configuration options:

| Configuration         | Description                                                                                                                                                                                                                                                                                                                 | Default        |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| namespace             | The namespace containing the ConfigMap                                                                                                                                                                                                                                                                                      | `spire`        |
| config_map            | The name of the ConfigMap                                                                                                                                                                                                                                                                                                   | `spire-bundle` |
| config_map_key        | The key within the ConfigMap for the bundle                                                                                                                                                                                                                                                                                 | `bundle.crt`   |
| kube_config_file_path | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, it is assumed the notifier is in-cluster and in-cluster credentials will be used. Required when configuring a remote cluster. See the `clusters` setting to configure multiple remote clusters. |                |
| api_service_label     | If set, rotate the CA Bundle in API services with this label set to `true`.                                                                                                                                                                                                                                                 |                |
| webhook_label         | If set, rotate the CA Bundle in validating and mutating webhooks with this label set to `true`.                                                                                                                                                                                                                             |                |
| clusters              | A list of remote cluster configurations. If set it can be used to configure multiple. Each cluster allows the same values as the root configuration.                                                                                                                                                                        |                |

## Configuring Kubernetes

The following actions are required to set up the plugin:

- Bind ClusterRole or Role that can `get` and `patch` the ConfigMap to Service Account.
  - In the case of in-cluster SPIRE server, it is Service Account that runs the SPIRE Server.
  - In the case of out-of-cluster SPIRE Server, it is Service Account that interacts with the Kubernetes API server.
  - In the case of setting `webhook_label`, the ClusterRole or Role additionally needs permissions to `get`, `list`, `patch`, and `watch` `mutatingwebhookconfigurations` and `validatingwebhookconfigurations`.
  - In the case of setting `api_service_label`, the ClusterRole or Role additionally needs permissions to `get`, `list`, `patch`, and `watch` `apiservices`.
- Create the ConfigMap that the plugin pushes.

For example:

In this example, assume that Service Account is `spire-server`.

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-cluster-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "patch"]

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-cluster-role-binding
subjects:
- kind: ServiceAccount
  name: spire-server
  namespace: spire
roleRef:
  kind: ClusterRole
  name: spire-server-cluster-role
  apiGroup: rbac.authorization.k8s.io

---

apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-bundle
  namespace: spire
```

### Configuration when Rotating Webhook and API Service CA Bundles

When rotating webhook and API Service CA bundles, use the below ClusterRole:

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-cluster-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "patch"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]
  verbs: ["get", "list", "patch", "watch"]
- apiGroups: ["apiregistration.k8s.io"]
  resources: ["apiservices"]
  verbs: ["get", "list", "patch", "watch"]
```

## Sample configurations

### Default In-Cluster with only ConfigMap Rotation

The following configuration pushes bundle contents from an in-cluster SPIRE
server to the `bundle.crt` key in the `spire:spire-bundle` ConfigMap.

```hcl
    Notifier "k8sbundle" {
        plugin_data {
        }
    }
```

### Out-Of-Cluster

The following configuration pushes bundle contents from an out-of-cluster SPIRE
server to the `boostrap.crt` key in the `infra:agents` ConfigMap using
the credentials found in the `/path/to/kubeconfig` file.

```hcl
    Notifier "k8sbundle" {
        plugin_data {
            namespace = "infra"
            config_map = "agents"
            config_map_key = "bootstrap.crt"
            kube_config_file_path = "/path/to/kubeconfig"
        }
    }
```

### Default In-Cluster with ConfigMap, Webhook, and APIService Rotation

The following configuration pushes bundle contents from an in-cluster SPIRE
server to

- The `bundle.crt` key in the `spire:spire-bundle` ConfigMap
- Validating and mutating webhooks with a label of `spiffe.io/webhook: true`
- API services with a label of `spiffe.io/api_service: true`

```hcl
    Notifier "k8sbundle" {
        plugin_data {
            webhook_label    = "spiffe.io/webhook"
            api_service_label = "spiffe.io/api_service"
        }
    }
```

### Multiple clusters

```hcl
    Notifier "k8sbundle" {
      plugin_data {        
        # local cluster
        namespace = "spire"

        # extra clusters
        clusters = [        
        {
          kube_config_file_path = "/cluster2/file/path"
        },
        {
          kube_config_file_path = "/cluster3/file/path"
        }
        ]
      }    
    }
```
