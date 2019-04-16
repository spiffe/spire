# Server plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the agent-side k8s_psat plugin*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The server
validates the signed projected service account token provided by the agent.
This validation is performed using Kubernetes [Token Review API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#tokenreview-v1-authentication-k8s-io). In addition to validation, this API provides other useful information (namespace, service account name and pod name) that SPIRE server uses to build selectors.
Kubernetes API server is also queried to get extra data like node name, which is used to generate a SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_psat/<cluster>/<node name>
```

The server does not need to be running in Kubernetes in order to perform node
attestation. In fact, the plugin can be configured to attest nodes running in
multiple clusters.

The main configuration accepts the following values:

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `clusters`      | A map of clusters, keyed by an arbitrary ID, that are authorized for attestation. | |

Each cluster in the main configuration requires the following configuration:

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `service_account_whitelist` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the whitelist. | |
| `audience` | Audience for token validation. If it is set to an empty array (`[]`), Kubernetes API server audience is used | ["spire-server"] |
| `kube_config_file` | Path to a k8s configuration file for API Server authentication. A kubernetes configuration file must be specified if SPIRE server runs outside of the k8s cluster. If empty, SPIRE server is assumed to be running inside the cluster and InClusterConfig is used. | ""|

A sample configuration for SPIRE server running inside k8s cluster:

```
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_whitelist = ["production:spire-agent"]
                }
        }
    }
```

This plugin generates the following selectors:

| Selector                   | Example                                | Description                                                                     |
| -------------------------- | ---------------------------------------| --------------------------------------------------------------------------------|
| `k8s_psat:cluster`         | `k8s_psat:cluster:MyCluster`           | Name of the cluster (from the plugin config) used to verify the token signature |
| `k8s_psat:agent_ns`        | `k8s_psat:agent_ns:production`         | Namespace that the agent is running under                                       |
| `k8s_psat:agent_sa`        | `k8s_psat:agent_sa:spire-agent`        | Service Account the agent is running under                                      |
| `k8s_psat:agent_pod_name`  | `k8s_psat:agent_pod_name:pod-name`     | Name of the pod in which the agent is running                                   |
| `k8s_psat:agent_pod_uid`   | `k8s_psat:agent_pod_uid:pod-uid`       | UID of the pod in which the agent is running                                    |
| `k8s_psat:agent_node_name` | `k8s_psat:agent_node_name:node-1`      | Name of the node in which the agent is runnig                                   |


A full example of this attestor is provided [here](../examples/k8s/simple_psat/README.md).