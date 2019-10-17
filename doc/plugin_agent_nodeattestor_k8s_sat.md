# Agent plugin: NodeAttestor "k8s_sat"

*Must be used in conjunction with the server-side k8s_sat plugin*

The `k8s_sat` plugin attests nodes running in inside of Kubernetes. The agent
reads and provides the signed service account token to the server.

*Note: If your cluster supports [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection)
you should instead consider using the `k8s_psat` attestor due to the [security considerations](#security-considerations) below.*

The server-side `k8s_sat` plugin generates a one-time UUID and generates a SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_sat/<cluster>/<UUID>
```

The main configuration accepts the following values:

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `cluster`       | Name of the cluster. It must correspond to a cluster configured in the server plugin. |
| `token_path`      | Path to the service account token on disk | "/run/secrets/kubernetes.io/serviceaccount/token" |

The token path defaults to the default location kubernetes uses to place the token and should not need to be overriden in most cases.

A sample configuration with the default token path:

```
    NodeAttestor "k8s_sat" {
        plugin_data {
            cluster = "MyCluster"
        }
    }
```

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
