# Agent plugin: WorkloadAttestor "k8s"

The `k8s` plugin generates kubernetes-based selectors for workloads calling the agent.
It does so by retrieving the workload's pod ID from its cgroup membership, then querying
the kubelet for information about the pod.

The plugin can talk to the kubelet via the insecure read-only port or the
secure port. Both X509 client authentication and bearer token (e.g. service
account token) authentication to the secure port is supported.

Verifying the certificate presented by the kubelet over the secure port is
optional. The default is to verify, based on the certificate file passed via
`kubelet_ca_path`. `skip_kubelet_verification` can be set to disable
verification.

The agent will contact the kubelet using the node name obtained via the
`node_name_env` or `node_name` configurables. If a node name is not obtained,
the kubelet is contacted over 127.0.0.1 (requires host networking to be
enabled). In the latter case, the hostname is used to perform certificate
server name validation against the kubelet certificate.

**Note** kubelet authentication via bearer token requires that the kubelet be
started with the `--authentication-token-webhook` flag. See [Kubelet authentication/authorization](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/)
for details.

**Note** The kubelet uses the TokenReview API to validate bearer tokens. This
requires reachability to the Kubernetes API server. Therefore API server downtime can
interrupt workload attestation. The `--authentication-token-webhook-cache-ttl` kubelet flag
controls how long the kubelet caches TokenReview responses and may help to
mitigate this issue. A large cache ttl value is not recommended however, as
that can impact permission revocation.

| Configuration | Description |
| ------------- | ----------- |
| `kubelet_read_only_port` | The kubelet read-only port. This is mutually exlusive with `kubelet_secure_port`. |
| `kubelet_secure_port` | The kubelet secure port. It defaults to `10250` unless `kubelet_read_only_port` is set. |
| `kubelet_ca_path` | The path on disk to a file containing CA certificates used to verify the kubelet certificate. Required unless `skip_kubelet_verification` is set. Defaults to the cluster CA bundle `/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `skip_kubelet_verification` | If true, kubelet certificate verification is skipped |
| `token_path` | The path on disk to the bearer token used for kubelet authentication. Defaults to the service account token `/run/secrets/kubernetes.io/serviceaccount/token` |
| `certificate_path` | The path on disk to client certificate used for kubelet authentication |
| `private_key_path` | The path on disk to client key used for kubelet authentication |
| `node_name_env` | The environment variable used to obtain the node name. Defaults to `MY_NODE_NAME`. |
| `node_name` | The name of the node. Overrides the value obtained by the environment variable specified by `node_name_env`. |

| Selector | Value |
| -------- | ----- |
| k8s:ns              | The workload's namespace |
| k8s:sa              | The workload's service account |
| k8s:container-image | The image of the workload's container |
| k8s:container-name  | The name of the workload's container |
| k8s:node-name       | The name of the workload's node |
| k8s:pod-label       | A label given to the the workload's pod |
| k8s:pod-owner       | The name of the workload's pod owner |
| k8s:pod-owner-uid   | The UID of the workload's pod owner |
| k8s:pod-uid         | The UID of the workload's pod |
| k8s:pod-name        | The name of the workload's pod |
| k8s:pod-images      | List of images of containers running in pod (sorted alphabetically) |
| k8s:pod-init-images | List of images of all init containers (sorted alphabetically) |

## Examples

To use the kubelet read-only port:

```
WorkloadAttestor "k8s" {
  plugin_data {
    kubelet_read_only_port = 10255
  }
}
```

To use the secure kubelet port, verify via `/run/secrets/kubernetes.io/serviceaccount/ca.crt`, and authenticate via the default service account token:

```
WorkloadAttestor "k8s" {
  plugin_data {
  }
}
```

To use the secure kubelet port, skip verification, and authenticate via the default service account token:

```
WorkloadAttestor "k8s" {
  plugin_data {
    skip_kubelet_verification = true
  }
}
```

To use the secure kubelet port, skip verification, and authenticate via some other token:

```
WorkloadAttestor "k8s" {
  plugin_data {
    skip_kubelet_verification = true
    token_path = "/path/to/token"
  }
}
```

To use the secure kubelet port, verify the kubelet certificate, and authenticate via an X509 client certificate:

```
WorkloadAttestor "k8s" {
  plugin_data {
    kubelet_ca_path = "/path/to/kubelet-ca.pem"
    certificate_path = "/path/to/cert.pem"
    private_key_path = "/path/to/key.pem"
  }
}
```
