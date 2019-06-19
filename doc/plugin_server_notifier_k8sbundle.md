# Server plugin: Notifier "k8sbundle"

The `k8sbundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to a Kubernetes
ConfigMap.

The certificates in the ConfigMap can be used to bootstrap SPIRE agents.

In HA, multiple SPIRE servers will be pushing bundle contents to the ConfigMap.
The plugin handles conflict resolution by implementing a read-modify-write
cycle to ensure the ConfigMap contains the latest bundle contents.

The plugin accepts the following configuration options:

| Configuration         | Description                                 | Default         |
| --------------------- | ------------------------------------------- | --------------- |
| namespace             | The namespace containing the ConfigMap      | `spire`         |
| config_map            | The name of the ConfigMap                   | `spire-bundle`  |
| config_map_key        | The key within the ConfigMap for the bundle | `bundle.crt`    |
| kube_config_file_path | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, it is assumed the notifier is in-cluster and in-cluster credentials will be used. | |

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
