# Server plugin: NodeAttestor "k8s_sat"

*Must be used in conjunction with the agent-side k8s_sat plugin*

The `k8s_sat` plugin attests nodes running in inside of Kubernetes. The server
validates the signed service account token provided by the agent. This validation is performed using the Kubernetes [Token Review API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#tokenreview-v1-authentication-k8s-io), from where the attestor also obtains the namespace and service account name.

The server uses a one-time UUID provided by the agent to generate a SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_sat/<cluster>/<UUID>
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
| `kube_config_file` | Path to a k8s configuration file for API Server authentication. A kubernetes configuration file must be specified if SPIRE server runs outside of the k8s cluster. If empty, SPIRE server is assumed to be running inside the cluster and in-cluster configuration is used. | "" |
| `service_account_whitelist` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the whitelist. | |

A sample configuration for SPIRE server running inside of a Kubernetes cluster:

```
    NodeAttestor "k8s_sat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_whitelist = ["production:spire-agent"]
                }
        }
    }
```

A sample configuration for SPIRE server running outside of a Kubernetes cluster:

```
    NodeAttestor "k8s_sat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_whitelist = ["production:spire-agent"]
                    kube_config_file = "path/to/kubeconfig/file"
                }
        }
    }
```

In addition, this plugin generates the following selectors:

| Selector           | Example                        | Description                                |
| -------------------| ------------------------------ | ------------------------------------------ |
| `k8s_sat:cluster`  | `k8s_sat:cluster:MyCluster`    | Name of the cluster (from the plugin config) used to verify the token signature |
| `k8s_sat:agent_ns` | `k8s_sat:agent_ns:production`  | Namespace that the agent is running under |
| `k8s_sat:agent_sa` | `k8s_sat:agent_sa:spire-agent` | Service Account the agent is running under |

## Security Considerations

At this time, the service account token does not contain claims that could be
used to strongly identify the node/daemonset/pod running the agent. This means
that any container running in a whitelisted service account can masquerade as
an agent, giving it access to any identity the agent is capable of issuing. It
is **STRONGLY** recommended that agents run under a dedicated service account.

It should be noted that due to the fact that SPIRE can't positively
identify a node using this method, it is not possible to directly authorize
identities for a distinct node or sets of nodes. Instead, this must be
accomplished indirectly using a service account and deployment that
leverages node affinity or node selectors.
