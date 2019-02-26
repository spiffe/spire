# Agent plugin: NodeAttestor "k8s_psat"

*Must be used in conjunction with the server-side k8s_psat plugin*

The `k8s_psat` plugin attests nodes running inside of Kubernetes. The agent
reads and provides the signed projected service account token (PSAT) to the server. It also
generates a one-time UUID that is also provided to the server.
In addition to service account data, PSAT embeds the pod name and UID on its claims. This allows
SPIRE to create more fine-grained attestation policies for agents.

The plugin generates SPIFFE IDs with the form:

```
spiffe://<trust domain>/spire/agent/k8s_psat/<cluster>/<UUID>
```

The main configuration accepts the following values:

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `cluster`       | Name of the cluster. It must correspond to a cluster configured in the server plugin. |
| `token_path`      | Path to the projected service account token on disk | "/var/run/secrets/tokens/psat" |


A sample configuration with the default token path:

```
    NodeAttestor "k8s_psat" {
        plugin_data {
            cluster = "MyCluster"
        }
    }
```

Its correspondient volume:
```
volumes:
    - name: psat
        projected:
        sources:
        - serviceAccountToken:
            path: psat
            expirationSeconds: 600
            audience: spire-server
```

And volume mount:
```
volumeMounts:
    - mountPath: /var/run/secrets/tokens
        name: psat
```

## Considerations

This attestor is based in two Kubernetes beta features (since k8s v1.12): Token Request and Token Request Projection. The first one allows a user to call the API Server to get a finely scoped service account token. The second one allows the user to specify a projection volume to automatically do the request and mount the token in a volume.