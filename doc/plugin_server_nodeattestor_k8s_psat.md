# Server plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the [agent-side k8s_psat plugin](plugin_agent_nodeattestor_k8s_psat.md)*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The server
validates the signed projected service account token provided by the agent.
This validation is performed using Kubernetes [Token Review API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#tokenreview-v1-authentication-k8s-io). In addition to validation, this API provides other useful information (namespace, service account name and pod name) that SPIRE server uses to build selectors.
Kubernetes API server is also queried to get extra data like node UID, which is used by default to generate a SPIFFE ID with the form:

```xml
spiffe://<trust_domain>/spire/agent/k8s_psat/<cluster>/<node UID>
```

A cluster can instead be configured to use the attesting pod UID for the generated agent SPIFFE ID:

```xml
spiffe://<trust_domain>/spire/agent/k8s_psat/<cluster>/pod/<pod UID>
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
| `use_pod_uid_for_agent_id`   | Use the attesting pod UID instead of the node UID when generating the agent SPIFFE ID. The pod UID is prefixed with `pod/` in the ID path.                                                                                                                                  | false            |

A sample configuration for SPIRE server running inside a Kubernetes cluster:

```hcl
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_allow_list = ["production:spire-agent"]
                    # use_pod_uid_for_agent_id = true
                }
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
                    # use_pod_uid_for_agent_id = true
                }
            }
        }
    }
```

## Running node-UID and pod-UID agents in one Kubernetes cluster

The keys in `clusters` are logical attestation profiles. They do not have to
correspond one-to-one with Kubernetes API servers. A single Kubernetes cluster
can have one server-side entry for agents that should use node UIDs in their
agent SPIFFE IDs and another entry for agents that should use pod UIDs.

```hcl
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyClusterNodes" = {
                    service_account_allow_list = ["spire:spire-agent"]
                }
                "MyClusterPods" = {
                    service_account_allow_list = ["spire:spire-broker-agent"]
                    use_pod_uid_for_agent_id = true
                }
            }
        }
    }
```

DaemonSet agents normally select the node-UID entry with the agent-side
`cluster = "MyClusterNodes"` setting. This preserves the usual one agent
identity per Kubernetes node. Deployment-based agents, or any other agents
where multiple agent pods may run on the same node, select the pod-UID entry
with `cluster = "MyClusterPods"` so each attesting pod gets a distinct concrete
agent SPIFFE ID.

Because the `k8s_psat:cluster:<name>` selector contains the logical cluster
entry name selected by the agent, node alias entries must match that name. For
example, a Deployment-based agent using the `spire:spire-broker-agent` Service
Account can have one stable alias entry for the group of pods with:

* Parent ID: `spiffe://<trust_domain>/spire/server`
* SPIFFE ID: the stable alias for that logical agent group
* Selectors: `k8s_psat:cluster:MyClusterPods`,
  `k8s_psat:agent_ns:spire`, and
  `k8s_psat:agent_sa:spire-broker-agent`

Registration entries can then use the alias as their parent ID. This keeps the
registration surface stable even though the concrete pod-UID agent IDs change
when Deployment pods are replaced.

This pattern is useful for a TCP-only [SPIFFE Broker API](spire_agent.md#spiffe-broker-api)
deployment. DaemonSet agents can keep using node-UID agent IDs for ordinary
Workload API traffic, while one or more Deployment-based agents use pod-UID
agent IDs to serve the Broker API over TCP. Broker SVID entries can remain
parented to the DaemonSet agent alias they use through the Workload API, and
object entries served by the Broker API can be parented to the Deployment-based
agent alias. When the k8s workload attestor uses
`experimental.broker.access_policy = "enforced"`, Kubernetes RBAC must also
allow the broker SPIFFE IDs to use SPIRE-specific `impersonate-via-spire` verb
on the referenced objects, as described in the
[k8s workload attestor Broker API documentation](plugin_agent_workloadattestor_k8s.md#broker-api).

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
