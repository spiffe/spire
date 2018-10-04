# Agent plugin: NodeAttestor "k8s_sat"

*Must be used in conjunction with the server-side k8s_sat plugin*

The `k8s_sat` plugin attests nodes running in inside of Kubernetes. The agent
reads and provides the signed service account token to the server. It also
generates a one-time UUID that is also provided to the server.

The SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_sat/<UUID>
```

The main configuration accepts the following values:

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `token_path`      | Path to the service account token on disk | "/run/secrets/kubernetes.io/serviceaccount/token" |

The token path defaults to the default location kubernetes uses to place the token and should not need to be overriden in most cases.

A sample configuration with the default token path:

```
    NodeAttestor "k8s_sat" {
        plugin_data {
        }
    }
```
