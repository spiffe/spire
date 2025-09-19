# Server plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the [agent-side k8s_psat plugin](plugin_agent_nodeattestor_k8s_psat.md)*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The server
validates the signed projected service account token provided by the agent.
This validation is performed using Kubernetes [Token Review API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#tokenreview-v1-authentication-k8s-io). In addition to validation, this API provides other useful information (namespace, service account name and pod name) that SPIRE server uses to build selectors.
Kubernetes API server is also queried to get extra data like node UID, which is used to generate a SPIFFE ID with the form:

```xml
spiffe://<trust_domain>/spire/agent/k8s_psat/<cluster>/<node UID>
```

The server does not need to be running in Kubernetes in order to perform node
attestation. In fact, the plugin can be configured to attest nodes running in
multiple clusters.

The main configuration accepts the following values:

| Configuration | Description                                                                       | Default |
|---------------|-----------------------------------------------------------------------------------|---------|
| `clusters`    | A map of clusters, keyed by an arbitrary ID, that are authorized for attestation. |         |

> [!WARNING]
> When `clusters` is empty, no clusters are authorized for attestation.

Each cluster in the main configuration requires the following configuration:

| Configuration                | Description                                                                                                                                                                                                                                                                 | Default          |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------|
| `service_account_allow_list` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the allow list.                                   |                  |
| `audience`                   | Audience for token validation. If it is set to an empty array (`[]`), Kubernetes API server audience is used                                                                                                                                                                | ["spire-server"] |
| `kube_config_file`           | Path to a k8s configuration file for API Server authentication. A kubernetes configuration file must be specified if SPIRE server runs outside of the k8s cluster. If empty, SPIRE server is assumed to be running inside the cluster and in-cluster configuration is used. | ""               |
| `allowed_node_label_keys`    | Node label keys considered for selectors                                                                                                                                                                                                                                    |                  |
| `allowed_pod_label_keys`     | Pod label keys considered for selectors                                                                                                                                                                                                                                     |                  |

A sample configuration for SPIRE server running inside a Kubernetes cluster:

```hcl
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_allow_list = ["production:spire-agent"]
                }
        }
    }
```

A sample configuration for SPIRE server running outside of a Kubernetes cluster:

```hcl
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_allow_list = ["production:spire-agent"]
                    kube_config_file = "path/to/kubeconfig/file"
                }
        }
    }
```

The Kubernetes user defined in the kube config file needs to have ClusterRoleBindings assigned to ClusterRoles containing at least the following permissions:

```yaml
- apiGroups: [""]
  resources: ["pods", "nodes"]
  verbs: ["get"]
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
```

This plugin generates the following selectors:

| Selector                    | Example                                                        | Description                                                                     |
|-----------------------------|----------------------------------------------------------------|---------------------------------------------------------------------------------|
| `k8s_psat:cluster`          | `k8s_psat:cluster:MyCluster`                                   | Name of the cluster (from the plugin config) used to verify the token signature |
| `k8s_psat:agent_ns`         | `k8s_psat:agent_ns:production`                                 | Namespace that the agent is running under                                       |
| `k8s_psat:agent_sa`         | `k8s_psat:agent_sa:spire-agent`                                | Service Account the agent is running under                                      |
| `k8s_psat:agent_pod_name`   | `k8s_psat:agent_pod_name:spire-agent-v5wgr`                    | Name of the pod in which the agent is running                                   |
| `k8s_psat:agent_pod_uid`    | `k8s_psat:agent_pod_uid:79261129-6b60-11e9-9054-0800277ac80f`  | UID of the pod in which the agent is running                                    |
| `k8s_psat:agent_pod_label`  | `k8s_psat:agent_pod_label:key:value`                           | Pod Label                                                                       |
| `k8s_psat:agent_node_ip`    | `k8s_psat:agent_node_ip:172.16.10.1`                           | IP address of the node in which the agent is running                            |
| `k8s_psat:agent_node_name`  | `k8s_psat:agent_node_name:minikube`                            | Name of the node in which the agent is running                                  |
| `k8s_psat:agent_node_uid`   | `k8s_psat:agent_node_uid:5dbb7b21-65fe-11e9-b1b0-0800277ac80f` | UID of the node in which the agent is running                                   |
| `k8s_psat:agent_node_label` | `k8s_psat:agent_node_label:key:value`                          | Node Label                                                                      |

The node and pod selectors are only provided for label keys in the `allowed_node_label_keys` and `allowed_pod_label_keys` configurables.

A full example of this attestor is provided in [the SPIRE examples repository](https://github.com/spiffe/spire-examples/tree/main/examples/k8s/simple_psat)
