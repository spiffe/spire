# Agent plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the server-side k8s_psat plugin*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The agent
reads and provides the signed projected service account token (PSAT) to the server.
In addition to service account data, PSAT embeds the pod name and UID on its claims. This allows
SPIRE to create more fine-grained attestation policies for agents.

The plugin generates SPIFFE IDs with the form:

```
spiffe://<trust domain>/spire/agent/k8s_psat/<cluster>/<POD UID>
```

The main configuration accepts the following values:

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `cluster`       | Name of the cluster. It must correspond to a cluster configured in the server plugin. | |
| `token_path`    | Path to the projected service account token on disk | "/var/run/secrets/tokens/spire-agent" |


A sample configuration with the default token path:

```
    NodeAttestor "k8s_psat" {
        plugin_data {
            cluster = "MyCluster"
        }
    }
```

Its k8s volume definition:
```
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
```
volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: spire-agent
```

## Considerations

This attestor is based on two Kubernetes beta features (since k8s v1.12): TokenRequest and TokenRequestProjection. TokenRequest exposes the ability to obtain finely scoped service account tokens from the Kubernetes API Server. TokenRequestProjection facilitates the automatic creation and mounting of such a token into a container.