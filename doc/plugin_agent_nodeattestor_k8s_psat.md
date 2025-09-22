# Agent plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the [server-side k8s_psat plugin](plugin_server_nodeattestor_k8s_psat.md)*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The agent
reads and provides the signed projected service account token (PSAT) to the server.
In addition to service account data, PSAT embeds the pod name and UID on its claims. This allows
SPIRE to create more fine-grained attestation policies for agents.

The [server-side `k8s_psat` plugin](plugin_server_nodeattestor_k8s_psat.md) will generate a SPIFFE ID on behalf of the agent of the form:

```xml
spiffe://<trust_domain>/spire/agent/k8s_psat/<cluster>/<node_UID>
```

The main configuration accepts the following values:

| Configuration | Description                                                                           | Default                               |
|---------------|---------------------------------------------------------------------------------------|---------------------------------------|
| `cluster`     | Name of the cluster. It must correspond to a cluster configured in the server plugin. |                                       |
| `token_path`  | Path to the projected service account token on disk                                   | "/var/run/secrets/tokens/spire-agent" |

A sample configuration with the default token path:

```hcl
    NodeAttestor "k8s_psat" {
        plugin_data {
            cluster = "MyCluster"
        }
    }
```

Its k8s volume definition:

```yaml
volumes:
    - name: spire-agent
      projected:
        sources:
        - serviceAccountToken:
            path: spire-agent
            expirationSeconds: 600
            audience: spire-server
```

And volume mount:

```yaml
volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: spire-agent
```

A full example of this attestor is provided in [the SPIRE examples repository](https://github.com/spiffe/spire-examples/tree/main/examples/k8s/simple_psat).
