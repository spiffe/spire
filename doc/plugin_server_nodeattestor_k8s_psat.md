# Server plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the agent-side k8s_psat plugin*

The `k8s_psat` plugin attests nodes running in inside of Kubernetes. The server
validates the signed projected service account token provided by the agent. It extracts
the service account name, pod name and namespace from the token claims. Optionally it can
query k8s API Server to get node information. The server uses the pod UID embeded
in the token to generate a SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_psat/<cluster>/<POD UID>
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
| `api_server_key_file` | Path on disk to a PEM encoded file containing public keys used in validating tokens for that cluster. RSA and ECDSA keys are supported. For RSA, X509 certificates, PKCS1, and PKIX encoded public keys are accepted. For ECDSA, X509 certificates, and PKIX encoded public keys are accepted. | |
| `service_account_whitelist` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the whitelist. | |
| `enable_api_server_queries` | If it is set to `true` SPIRE server queries k8s API server for additional selectors | false |
| `kube_config_file` | Only used if `enable_api_server_queries` is `true`. Path to a k8s configuration file for API Server authentication. A kubernetes configuration file must be specified if SPIRE server runs out of k8s cluster. If empty, SPIRE server is assumed to be running inside cluster and InClusterConfig is used. | ""|

A sample configuration for SPIRE server running inside k8s cluster:

```
    NodeAttestor "k8s_psat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_key_file = "/path/to/key/file"
                    service_account_whitelist = ["production:spire-agent"]
                    enable_api_server_queries = true
                }
        }
    }
```

This plugin generates the following selectors:

| Selector              | Example                                | Description                                                                     |
| ----------------------| ---------------------------------------| --------------------------------------------------------------------------------|
| `k8s_psat:cluster`    | `k8s_psat:cluster:MyCluster`           | Name of the cluster (from the plugin config) used to verify the token signature |
| `k8s_psat:agent_ns`   | `k8s_psat:agent_ns:production`         | Namespace that the agent is running under                                       |
| `k8s_psat:agent_sa`   | `k8s_psat:agent_sa:spire-agent`        | Service Account the agent is running under                                      |
| `k8s_psat:agent_pod`  | `k8s_psat:agent_pod:spire-agent-pod`   | Pod prefix in which the agent is running                                        |


In addition, if `enable_api_server_queries` is enabled, also the following selectors are a generated:

| Selector              | Example                                | Description                                                                     |
| ----------------------| ---------------------------------------| --------------------------------------------------------------------------------|
| `k8s_psat:agent_node` | `k8s_psat:agent_node:node-1`           | Node in which the agent is running                                              |