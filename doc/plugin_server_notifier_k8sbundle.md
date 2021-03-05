# Server plugin: Notifier "k8sbundle"

The `k8sbundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to a Kubernetes
ConfigMap.

The certificates in the ConfigMap can be used to bootstrap SPIRE agents.

The plugin accepts the following configuration options:

| Configuration         | Description                                 | Default         |
| --------------------- | ------------------------------------------- | --------------- |
| namespace             | The namespace containing the ConfigMap      | `spire`         |
| config_map            | The name of the ConfigMap                   | `spire-bundle`  |
| config_map_key        | The key within the ConfigMap for the bundle | `bundle.crt`    |
| kube_config_file_path | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, it is assumed the notifier is in-cluster and in-cluster credentials will be used. | |
| label                 | If set, rotate the CA Bundle in validating and mutating webhooks with this label set to `true`. | |

## Configuring Kubernetes

The following actions are required to set up the plugin.

- Bind ClusterRole or Role that can `get` and `patch` the ConfigMap to Service Account
    - In the case of in-cluster SPIRE server, it is Service Account that runs the SPIRE server
    - In the case of out-of-cluster SPIRE server, it is Service Account that interacts with the Kubernetes API server
    - In the case of setting `label`, the ClusterRole additionally needs permissions to `get`, `list`, `patch`, and `watch` `mutatingwebhookconfigurations` and `validatingwebhookconfigurations`.
- Create the ConfigMap that the plugin pushes

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

### Configuration when Rotating Webhook CA Bundles
When rotating webhook CA bundles, use the below ClusterRole:

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
```

## Sample configurations

### Default In-Cluster

The following configuration pushes bundle contents from an in-cluster SPIRE
server to the `bundle.crt` key in the `spire:spire-bundle` ConfigMap.

```
    Notifier "k8sbundle" {
        plugin_data {
        }
    }
```

### Out-Of-Cluster

The following configuration pushes bundle contents from an out-of-cluster SPIRE
server to the `boostrap.crt` key in the `infra:agents` ConfigMap using
the credentials found in the `/path/to/kubeconfig` file.

```
    Notifier "k8sbundle" {
        plugin_data {
            namespace = "infra"
            config_map = "agents"
            config_map_key = "bootstrap.crt"
            kube_config_file_path = "/path/to/kubeconfig"
        }
    }
```

### Default In-Cluster with Webhook Rotation
The following configuration pushes bundle contents from an in-cluster SPIRE
server to
- The `bundle.crt` key in the `spire:spire-bundle` ConfigMap
- Validating and mutating webhooks with a label of `spiffe.io/webhook: true`

```
    Notifier "k8sbundle" {
        plugin_data {
            webhook_label = "spiffe.io/webhook"
        }
    }
```
