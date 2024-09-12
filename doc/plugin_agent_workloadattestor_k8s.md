# Agent plugin: WorkloadAttestor "k8s"

The `k8s` plugin generates Kubernetes-based selectors for workloads calling the agent.
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

> **Note** kubelet authentication via bearer token requires that the kubelet be
> started with the `--authentication-token-webhook` flag.
> See [Kubelet authentication/authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
> for details.

<!-- different notes -->

> **Note** The kubelet uses the TokenReview API to validate bearer tokens.
> This requires reachability to the Kubernetes API server. Therefore API server downtime can
> interrupt workload attestation. The `--authentication-token-webhook-cache-ttl` kubelet flag
> controls how long the kubelet caches TokenReview responses and may help to
> mitigate this issue. A large cache ttl value is not recommended however, as
> that can impact permission revocation.

<!-- different notes -->

> **Note** Anonymous authentication with the kubelet requires that the
> kubelet be started with the `--anonymous-auth` flag. It is discouraged to use anonymous
> auth mode in production as it requires authorizing anonymous users to the `nodes/proxy`
> resource that maps to some privileged operations, such as executing commands in
> containers and reading pod logs.

<!-- different notes -->

**Note** To run on Windows containers, Kubernetes v1.24+ and containerd v1.6+ are required,
since [hostprocess](https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/) container is required on the agent container.

| Configuration                    | Description                                                                                                                                                                                                                             |
|--------------------------------  |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `disable_container_selectors`    | If true, container selectors are not produced. This can be used to produce pod selectors when the workload pod is known but the workload container is not ready at the time of attestation.                                             |
| `kubelet_read_only_port`         | The kubelet read-only port. This is mutually exclusive with `kubelet_secure_port`.                                                                                                                                                      |
| `kubelet_secure_port`            | The kubelet secure port. It defaults to `10250` unless `kubelet_read_only_port` is set.                                                                                                                                                 |
| `kubelet_ca_path`                | The path on disk to a file containing CA certificates used to verify the kubelet certificate. Required unless `skip_kubelet_verification` is set. Defaults to the cluster CA bundle `/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `skip_kubelet_verification`      | If true, kubelet certificate verification is skipped                                                                                                                                                                                    |
| `token_path`                     | The path on disk to the bearer token used for kubelet authentication. Defaults to the service account token `/run/secrets/kubernetes.io/serviceaccount/token`                                                                           |
| `certificate_path`               | The path on disk to client certificate used for kubelet authentication                                                                                                                                                                  |
| `private_key_path`               | The path on disk to client key used for kubelet authentication                                                                                                                                                                          |
| `use_anonymous_authentication`   | If true, use anonymous authentication for kubelet communication                                                                                                                                                                         |
| `node_name_env`                  | The environment variable used to obtain the node name. Defaults to `MY_NODE_NAME`.                                                                                                                                                      |
| `node_name`                      | The name of the node. Overrides the value obtained by the environment variable specified by `node_name_env`.                                                                                                                            |
| `experimental`                   | The experimental options that are subject to change or removal.                                                                                                                                                                         |
| `use_new_container_locator`      | If true, enables the new container locator algorithm that has support for cgroups v2. Defaults to true.                                                                                                                                 |
| `verbose_container_locator_logs` | If true, enables verbose logging of mountinfo and cgroup information used to locate containers. Defaults to false.                                                                                                                      |

## Sigstore experimental feature

This feature extends the `k8s` workload attestor with the ability to validate container image signatures and attestations using the [Sigstore](https://www.sigstore.dev/) ecosystem.

### Experimental options

| Option     | Description                                                                               |
|------------|-------------------------------------------------------------------------------------------|
| `sigstore` | Sigstore options. Options described below. See [Sigstore options](#sigstore-options)      |

### Sigstore options

| Option                 | Description                                                                                                                                                                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allowed_identities`   | Maps OIDC Provider URIs to lists of allowed subjects. Supports regular expressions patterbs. Defaults to empty. If unspecified, signatures from any issuer are accepted. (eg. `"https://accounts.google.com" = ["subject1@example.com","subject2@example.com"]`). |
| `skipped_images`       | Lists image IDs to exclude from Sigstore signature verification. For these images, no Sigstore selectors will be generated. Defaults to an empty list.                                                                                                            |
| `rekor_url`            | Specifies the Rekor URL for transparency log verification. Default is the public Rekor instance [https://rekor.sigstore.dev](https://rekor.sigstore.dev).                                                                                                         |
| `ignore_tlog`          | If set to true, bypasses the transparency log verification and the selectors based on the Rekor bundle are not generated.                                                                                                                                         |
| `ignore_attestations`  | If set to true, bypasses the image attestations verification and the selector `image-attestations:verified` is not generated.                                                                                                                                     |
| `ignore_sct`           | If set to true, bypasses the Signed Certificate Timestamp (SCT) verification.                                                                                                                                                                                     |
| `registry_credentials` | Maps each registry URL to its corresponding authentication credentials. Example: `{"docker.io": {"username": "user", "password": "pass"}}`.                                                                                                                       |

#### Custom CA Roots

Custom CA roots signed through TUF can be provided using the `cosign initialize` command. This method securely pins the
CA roots, ensuring that only trusted certificates are used during validation. Additionally, trusted roots for
certificate validation can be specified via the `SIGSTORE_ROOT_FILE` environment variable. For more details on Cosign
configurations, refer to the [documentation](https://github.com/sigstore/cosign/blob/main/README.md).

### K8s selectors

| Selector                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                  |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| k8s:ns                   | The workload's namespace                                                                                                                                                                                                                                                                                                                                                                                               |
| k8s:sa                   | The workload's service account                                                                                                                                                                                                                                                                                                                                                                                         |
| k8s:container-image      | The Image OR ImageID of the container in the workload's pod which is requesting an SVID, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb` |
| k8s:container-name       | The name of the workload's container                                                                                                                                                                                                                                                                                                                                                                                   |
| k8s:node-name            | The name of the workload's node                                                                                                                                                                                                                                                                                                                                                                                        |
| k8s:pod-label            | A label given to the workload's pod                                                                                                                                                                                                                                                                                                                                                                                    |
| k8s:pod-owner            | The name of the workload's pod owner                                                                                                                                                                                                                                                                                                                                                                                   |
| k8s:pod-owner-uid        | The UID of the workload's pod owner                                                                                                                                                                                                                                                                                                                                                                                    |
| k8s:pod-uid              | The UID of the workload's pod                                                                                                                                                                                                                                                                                                                                                                                          |
| k8s:pod-name             | The name of the workload's pod                                                                                                                                                                                                                                                                                                                                                                                         |
| k8s:pod-image            | An Image OR ImageID of any container in the workload's pod, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb`                              |
| k8s:pod-image-count      | The number of container images in workload's pod                                                                                                                                                                                                                                                                                                                                                                       |
| k8s:pod-init-image       | An Image OR ImageID of any init container in the workload's pod, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb`                         |
| k8s:pod-init-image-count | The number of init container images in workload's pod                                                                                                                                                                                                                                                                                                                                                                  |

Sigstore enabled selectors (available when configured to use `sigstore`)

| Selector                                   | Value                                                                                                                                                                                                                                     |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| k8s:image-signature:verified               | When the image signature was verified and is valid.                                                                                                                                                                                       |
| k8s:image-attestations:verified            | When the image attestations were verified and are valid.                                                                                                                                                                                  |
| k8s:image-signature-value                  | The base64 encoded value of the signature (eg. `k8s:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=`)                                                            |
| k8s:image-signature-subject                | The OIDC principal that signed the image (e.g., `k8s:image-signature-subject:spirex@example.com`)                                                                                                                                         |
| k8s:image-signature-issuer                 | The OIDC issuer of the signature (e.g., `k8s:image-signature-issuer:https://accounts.google.com`)                                                                                                                                         |
| k8s:image-signature-log-id                 | A unique LogID for the Rekor transparency log entry (eg. `k8s:image-signature-log-id:c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b95918123`)                                                                                   |
| k8s:image-signature-log-index              | The log index for the Rekor transparency log entry (eg. `k8s:image-signature-log-index:105695637`)                                                                                                                                        |
| k8s:image-signature-integrated-time        | The time (in Unix timestamp format) when the image signature was integrated into the signature transparency log (eg. `k8s:image-signature-integrated-time:1719237832`)                                                                    |
| k8s:image-signature-signed-entry-timestamp | The base64 encoded signed entry (signature over the logID, logIndex, body and integratedTime) (eg. `k8s:image-signature-integrated-time:MEQCIDP77vB0/MEbR1QKZ7Ol8PgFwGEEvnQJiv5cO7ATDYRwAiB9eBLYZjclxRNaaNJVBdQfP9Y8vGVJjwdbisme2cKabc`)  |

If `ignore_tlog` is set to `true`, the selectors based on the Rekor bundle (`-log-id`, `-log-index`, `-integrated-time`, and `-signed-entry-timestamp`) are not generated.

> **Note** `container-image` will ONLY match against the specific container in the pod that is contacting SPIRE on behalf of
> the pod, whereas `pod-image` and `pod-init-image` will match against ANY container or init container in the Pod,
> respectively.

## Examples

To use the kubelet read-only port:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    kubelet_read_only_port = 10255
  }
}
```

To use the secure kubelet port, verify via `/run/secrets/kubernetes.io/serviceaccount/ca.crt`, and authenticate via the default service account token:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
  }
}
```

To use the secure kubelet port, skip verification, and authenticate via the default service account token:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    skip_kubelet_verification = true
  }
}
```

To use the secure kubelet port, skip verification, and authenticate via some other token:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    skip_kubelet_verification = true
    token_path = "/path/to/token"
  }
}
```

To use the secure kubelet port, verify the kubelet certificate, and authenticate via an X509 client certificate:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    kubelet_ca_path = "/path/to/kubelet-ca.pem"
    certificate_path = "/path/to/cert.pem"
    private_key_path = "/path/to/key.pem"
  }
}
```

### Platform support

This plugin is only supported on Unix systems.

### Known issues

* This plugin may fail to correctly attest workloads in pods that use lifecycle hooks to alter pod start behavior. This includes Istio workloads when the `holdApplicationUntilProxyStarts` configurable is set to true. Please see [#3092](https://github.com/spiffe/spire/issues/3092) for more information. The `disable_container_selectors` configurable can be used to successfully attest workloads in this situation, albeit with reduced selector granularity (i.e. pod selectors only).
