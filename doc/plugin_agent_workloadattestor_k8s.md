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

| Configuration                  | Description                                                                                                                                                                                                                             |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `disable_container_selectors`  | If true, container selectors are not produced. This can be used to produce pod selectors when the workload pod is known but the workload container is not ready at the time of attestation.                                             |
| `kubelet_read_only_port`       | The kubelet read-only port. This is mutually exclusive with `kubelet_secure_port`.                                                                                                                                                      |
| `kubelet_secure_port`          | The kubelet secure port. It defaults to `10250` unless `kubelet_read_only_port` is set.                                                                                                                                                 |
| `kubelet_ca_path`              | The path on disk to a file containing CA certificates used to verify the kubelet certificate. Required unless `skip_kubelet_verification` is set. Defaults to the cluster CA bundle `/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `skip_kubelet_verification`    | If true, kubelet certificate verification is skipped                                                                                                                                                                                    |
| `token_path`                   | The path on disk to the bearer token used for kubelet authentication. Defaults to the service account token `/run/secrets/kubernetes.io/serviceaccount/token`                                                                           |
| `certificate_path`             | The path on disk to client certificate used for kubelet authentication                                                                                                                                                                  |
| `private_key_path`             | The path on disk to client key used for kubelet authentication                                                                                                                                                                          |
| `use_anonymous_authentication` | If true, use anonymous authentication for kubelet communication                                                                                                                                                                         |
| `node_name_env`                | The environment variable used to obtain the node name. Defaults to `MY_NODE_NAME`.                                                                                                                                                      |
| `node_name`                    | The name of the node. Overrides the value obtained by the environment variable specified by `node_name_env`.                                                                                                                            |
| `experimental`                 | The experimental options that are subject to change or removal.                                                                                                                                                                         |

| Experimental options | Description                                                                                                                  |
|----------------------|----------------------------------------------------------------------------------------------------------------------------- |
| `sigstore`           | Sigstore options. Options described below. See [Sigstore workload attestor for SPIRE](#sigstore-workload-attestor-for-spire) |

| Sigstore options                         | Description                                                                                                                                                                                                                                                                                                                                                         |
|------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `skip_signature_verification_image_list` | The list of images, described as digest hashes, that should be skipped in signature verification. Defaults to empty list.                                                                                                                                                                                                                                           |
| `allowed_subjects_list`                  | A map of allowed subject strings, keyed by the OIDC Provider URI, that are trusted and are allowed to sign container images artifacts. Defaults to empty. If empty, no workload will pass signature validation, unless listed on `skip_signature_verification_image_list`. (eg. `"https://accounts.google.com" = ["subject1@example.com","subject2@example.com"]`). |
| `rekor_url`                              | The rekor URL to use with cosign. Required. See notes below.                                                                                                                                                                                                                                                                                                        |
| `enforce_sct`                            | A boolean to be set to false in case of a private deployment, not using public CT                                                                                                                                                                                                                                                                                   |

> **Note** Cosign discourages the use of image tags for referencing docker images, and this plugin does not support attestation of sigstore selectors for workloads running on containers using tag-referenced images, which will then fail attestation for both sigstore and k8s selectors. In cases where this is necessary, add the digest string for the image in the `skip_signature_verification_image_list` setting (eg. `"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"`). Note that sigstore signature attestation will still not be performed, but this will allow k8s selectors to be returned, along with the `"k8s:sigstore-validation:passed"` selector.

<!-- different notes -->

> **Note** Since the SPIRE Agent can also go through workload attestation, it will also need to be included in the skip list if either its image is not signed or has a digest reference string.

<!-- different notes -->

> **Note** The sigstore project contains a transparency log called Rekor that provides an immutable, tamper-resistant ledger to record signed metadata to an immutable record. While it is possible to run your own instance, a public instance of rekor is available at `https://rekor.sigstore.dev/`.

## Sigstore workload attestor for SPIRE

### Platform support

This capability is only supported on Unix systems.

The k8s workload attestor plugin also has capabilities to validate container images signatures through [sigstore](https://www.sigstore.dev/)

Cosign supports container signing, verification, and storage in an OCI registry. Cosign aims to make signatures invisible infrastructure. For this, we’ve chosen the Sigstore ecosystem and artifacts. Digging deeper, we are using: Rekor (signature transparency log), Fulcio (signing certificate issuer and certificate transparency log) and Cosign (container image signing tool) to guarantee the authenticity of the running workload.

> **Note** you can provide your own CA roots signed through TUF via the cosign initialize command.
This effectively securely pins the CA roots. We allow you to also specify trusted roots via the `SIGSTORE_ROOT_FILE` flag

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

Sigstore enabled selectors (available when configured to use sigstore)

| Selector                                           | Value                                                                                                                                                                                                                                                      |
|----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| k8s:${containerID}:image-signature-content         | A containerID is an unique alphanumeric number for each container. The value of the signature itself in a hash (eg. "k8s:000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=") |
| k8s:${containerID}:image-signature-subject         | OIDC principal that signed it​ (eg. "k8s:000000:image-signature-subject:spirex@example.com")                                                                                                                                                               |
| k8s:${containerID}:image-signature-logid           | A unique LogID for the Rekor transparency log​ (eg. "k8s:000000:image-signature-logid:samplelogID")                                                                                                                                                        |
| k8s:${containerID}:image-signature-integrated-time | The time (in Unix timestamp format) when the image signature was integrated into the signature transparency log​ (eg. "k8s:000000:image-signature-integrated-time:12345")                                                                                  |
| k8s:sigstore-validation                            | The confirmation if the signature is valid, has value of "passed" (eg. "k8s:sigstore-validation:passed")                                                                                                                                                   |
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
