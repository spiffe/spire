# Server plugin: NodeAttestor "k8s_sat"

*Must be used in conjunction with the agent-side k8s_sat plugin*

The `k8s_sat` plugin attests nodes running in inside of Kubernetes. The server
validates the signed service account token provided by the agent. It extracts
the service account name and namespace from the token claims. The server uses a
one-time UUID provided by the agent for generate a SPIFFE ID with the form:

```
spiffe://<trust domain>/spire/agent/k8s_sat/<UUID>
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
| `service_account_key_file` | Path on disk to a PEM encoded file containing public keys used in validating tokens for that cluster. RSA and ECDSA keys are supported. For RSA, X509 certificates, PKCS1, and PKIX encoded public keys are accepted. For ECDSA, X509 certificates, and PKIX encoded public keys are accepted. | |
| `service_account_whitelist` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the whitelist. | |

A sample configuration:

```
    NodeAttestor "k8s_sat" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_key_file = "/path/to/key/file"
                    service_account_whitelist = ["production:spire-agent"]
                }
        }
    }
```

In addition, this plugin generates the following selectors of type `k8s_sat` for each node:

| Value                       | Example                       | Description                                |
| --------------------------- | ----------------------------- | ------------------------------------------ |
| `cluster-name`              | `cluster-name:MyCluster`      | Name of the cluster (from the plugin config) used to verify the token signature |
| `service-account:namespace` | `service-account:production`  | Namespace of the service account           |
| `service-account:name`      | `service-account:spire-agent` | Name of the service account                |

