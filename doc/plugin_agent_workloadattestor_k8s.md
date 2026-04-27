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
> This requires reachability to the Kubernetes API server. Therefore, API server downtime can
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

| Configuration                           | Description                                                                                                                                                                                                                             |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `experimental.api_server.cache.enabled` | If true, enables a controller-runtime Kubernetes API server cache for object-reference lookups. Defaults to false.                                                                                                                      |
| `disable_container_selectors`           | If true, container selectors are not produced. This can be used to produce pod selectors when the workload pod is known but the workload container is not ready at the time of attestation.                                             |
| `kubelet_read_only_port`                | The kubelet read-only port. This is mutually exclusive with `kubelet_secure_port`.                                                                                                                                                      |
| `kubelet_secure_port`                   | The kubelet secure port. It defaults to `10250` unless `kubelet_read_only_port` is set.                                                                                                                                                 |
| `kubelet_ca_path`                       | The path on disk to a file containing CA certificates used to verify the kubelet certificate. Required unless `skip_kubelet_verification` is set. Defaults to the cluster CA bundle `/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `skip_kubelet_verification`             | If true, kubelet certificate verification is skipped                                                                                                                                                                                    |
| `token_path`                            | The path on disk to the bearer token used for kubelet authentication. Defaults to the service account token `/run/secrets/kubernetes.io/serviceaccount/token`                                                                           |
| `certificate_path`                      | The path on disk to client certificate used for kubelet authentication                                                                                                                                                                  |
| `private_key_path`                      | The path on disk to client key used for kubelet authentication                                                                                                                                                                          |
| `use_anonymous_authentication`          | If true, use anonymous authentication for kubelet communication                                                                                                                                                                         |
| `node_name_env`                         | The environment variable used to obtain the node name. Defaults to `MY_NODE_NAME`.                                                                                                                                                      |
| `node_name`                             | The name of the node. Overrides the value obtained by the environment variable specified by `node_name_env`.                                                                                                                            |
| `experimental.broker`                   | Experimental Broker API options for `AttestReference`. Required when this plugin handles Broker API references. See [Broker API](#broker-api).                                                                                          |
| `sigstore`                              | Sigstore options. Options described below. See [Sigstore options](#sigstore-options). When set, enables verification of container image signatures and attestations.                                                                    |
| `use_new_container_locator`             | If true, enables the new container locator algorithm that has support for cgroups v2. Defaults to true.                                                                                                                                 |
| `verbose_container_locator_logs`        | If true, enables verbose logging of mountinfo and cgroup information used to locate containers. Defaults to false.                                                                                                                      |

## Sigstore feature

This feature extends the `k8s` workload attestor with the ability to validate container image signatures and attestations using the [Sigstore](https://www.sigstore.dev/) ecosystem. It is optional and only enabled when the `sigstore` block is configured.

### Sigstore options

| Option                 | Description                                                                                                                                                                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allowed_identities`   | Maps OIDC Provider URIs to lists of allowed subjects. Supports regular expressions patterns. Defaults to empty. If unspecified, signatures from any issuer are accepted. (eg. `"https://accounts.google.com" = ["subject1@example.com","subject2@example.com"]`). |
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

## K8s selectors

| Selector                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| k8s:ns                   | The workload's namespace                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| k8s:sa                   | The workload's service account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| k8s:container-image      | The Image OR ImageID of the container in the workload's pod which is requesting an SVID, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb`. See [image selector limitations](#image-selector-limitations) for important caveats when using tag-based selectors. |
| k8s:container-name       | The name of the workload's container                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| k8s:node-name            | The name of the workload's node                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| k8s:pod-label            | A label given to the workload's pod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| k8s:pod-owner            | The name of the workload's pod owner                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| k8s:pod-owner-uid        | The UID of the workload's pod owner                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| k8s:pod-uid              | The UID of the workload's pod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| k8s:pod-name             | The name of the workload's pod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| k8s:pod-image            | An Image OR ImageID of any container in the workload's pod, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb`. See [image selector limitations](#image-selector-limitations) for important caveats when using tag-based selectors.                              |
| k8s:pod-image-count      | The number of container images in workload's pod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| k8s:pod-init-image       | An Image OR ImageID of any init container in the workload's pod, [as reported by K8S](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus). Selector value may be an image tag, such as: `docker.io/envoyproxy/envoy-alpine:v1.16.0`, or a resolved SHA256 image digest, such as `docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb`. See [image selector limitations](#image-selector-limitations) for important caveats when using tag-based selectors.                         |
| k8s:pod-init-image-count | The number of init container images in workload's pod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

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

## Broker API

When SPIRE Agent's [SPIFFE Broker API](spire_agent.md#spiffe-broker-api) is
enabled, the k8s workload attestor handles Broker API `AttestReference`
requests for `WorkloadPIDReference` and `KubernetesObjectReference`.
`AttestReference` requires an `experimental.broker` block in the plugin configuration. Each
`experimental.broker.brokers` entry identifies one broker SPIFFE ID that may use this
plugin. Broker IDs must be valid, unique, and non-empty. The required
block-level `access_policy` setting controls whether the plugin creates
Kubernetes `SubjectAccessReview` requests for resolved objects. Use
`access_policy = "enforced"` to authorize every resolved object with
Kubernetes before selectors are returned. Use `access_policy = "permissive"`
to skip that authorization check. Each broker may set `pod_reference_scope` to
`agent_node` (default) or `cluster`; this only affects pod
`KubernetesObjectReference` resolution.

Example:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    experimental {
      broker {
        access_policy = "enforced"
        brokers = [
          {
            id = "spiffe://example.org/broker"
            pod_reference_scope = "cluster"
          }
        ]
      }
    }
  }
}
```

`WorkloadPIDReference` follows the PID-based k8s attestation path to
resolve the workload pod and selectors. When that Broker API reference
resolves to a pod and `experimental.broker.access_policy = "enforced"`, the plugin creates a
`SubjectAccessReview` asking whether the broker SPIFFE ID may use SPIRE's
custom Kubernetes authorization verb `impersonate-via-spire` on the resolved
pod. The review uses the broker SPIFFE ID as the SAR username and does not
set groups. PID-based attestation via the workload attestor's `Attest` RPC
does not use the broker configuration or run this review.

For `KubernetesObjectReference`, the reference identifies the target object by
its resource (`<plural>.<group>`, with `core` as the group string for core
resources) and either its namespaced name (`namespace` + `name`), its `uid`,
or both. Pod references try the local kubelet pod list first. With the default
`pod_reference_scope = "agent_node"`, pod references are limited to information
returned by the local kubelet and do not fall back to the Kubernetes API
server. With `pod_reference_scope = "cluster"`, pod references may fall back to
the Kubernetes API server and resolve pods on any node. Non-pod object
references are resolved through the Kubernetes API server. When
`experimental.broker.access_policy = "enforced"`, the plugin then creates the same
`SubjectAccessReview` for the referenced object. The review uses the broker
SPIFFE ID as the SAR username, no groups, the reference's resource group and
plural, and the resolved namespace and name. If the authorizer denies the
review, attestation fails with `PermissionDenied`. Kubernetes API server
lookups require the agent ServiceAccount to have permission for the referenced
resource.

**Pods (`pods/core`).** A `KubernetesObjectReference` to a pod is attested
through the same pod-resolution path as the PID-based reference and emits
the **same** pod-shaped selectors documented in the table above
(`k8s:ns`, `k8s:sa`, `k8s:pod-name`, `k8s:container-name`, `k8s:pod-uid`,
`k8s:pod-label`, `k8s:pod-image`, `k8s:pod-owner`, ...). By default, broker
pod references are limited to pods returned by the local kubelet
(`agent_node`). Set `pod_reference_scope = "cluster"` for a broker that must
reference pods on other nodes through the Kubernetes API server. A registration
entry written for the PID-based flow continues to match either reference type.

**Other resources (any `<plural>.<group>` for which the agent has permission).**
The agent fetches the object's `metadata` via the Kubernetes API server
(using a `PartialObjectMetadata` request) and emits a uniform vocabulary
that is independent of the resource's kind:

| Selector                | Value                                                                                                       |
|-------------------------|-------------------------------------------------------------------------------------------------------------|
| k8s:uid                 | The object's UID.                                                                                           |
| k8s:resource            | `<plural>.<group>` for the resource (e.g. `deployments.apps`, `pods.core`).                                 |
| k8s:plural              | The resource plural (e.g. `deployments`).                                                                   |
| k8s:group               | The API group (e.g. `apps`); `core` for core resources.                                                     |
| k8s:version             | The discovered version (e.g. `v1`, `v1beta1`).                                                              |
| k8s:apiVersion          | The Kubernetes wire form: `v1` for core or `<group>/<version>` otherwise.                                   |
| k8s:kind                | The object kind (e.g. `Deployment`).                                                                        |
| k8s:name                | The object name.                                                                                            |
| k8s:namespace           | The object namespace; omitted for cluster-scoped objects.                                                   |
| k8s:key                 | `<namespace>/<name>` for namespaced objects, or just `<name>` for cluster-scoped ones.                      |
| k8s:label               | A label on the object, formatted `<key>:<value>` (one selector per label entry).                            |
| k8s:owner-key           | `<group>/<Kind>/<name>` for each entry in `metadata.ownerReferences`.                                       |
| k8s:owner-uid           | `<group>/<Kind>/<uid>` for each entry in `metadata.ownerReferences`.                                        |
| k8s:controller-key      | Same as `k8s:owner-key`, but only emitted for owner references with `Controller: true`.                     |
| k8s:controller-uid      | Same as `k8s:owner-uid`, but only emitted for owner references with `Controller: true`.                     |

Annotations are intentionally **not** exposed as selectors. Kubernetes labels
are validated and indexed by the API server and are the appropriate identity
anchor; annotations are an unconstrained metadata grab bag (often multi-line
JSON) that does not fit equality-matched selectors.

The agent's ServiceAccount needs `get` (and `list` when references identify
objects by `uid` alone) permission on every resource it is expected to
resolve via this path. When `experimental.broker.access_policy = "enforced"`, it also needs
`create` on `subjectaccessreviews.authorization.k8s.io` to perform broker
authorization checks. For example:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spire-agent-k8s-attestor
rules:
  # Object-reference resolution. Add every resource brokers may reference.
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: ["kustomize.toolkit.fluxcd.io"]
    resources: ["kustomizations"]
    verbs: ["get", "list"]

  # Required only when experimental.broker.access_policy = "enforced", so the k8s workload
  # attestor can create SubjectAccessReview objects while handling Broker API
  # reference requests.
  - apiGroups: ["authorization.k8s.io"]
    resources: ["subjectaccessreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spire-agent-k8s-attestor
subjects:
  - kind: ServiceAccount
    name: spire-agent
    namespace: spire
roleRef:
  kind: ClusterRole
  name: spire-agent-k8s-attestor
  apiGroup: rbac.authorization.k8s.io
```

When `experimental.broker.access_policy = "enforced"`, the Kubernetes authorizer must also allow
the broker SPIFFE ID to use SPIRE's custom **`impersonate-via-spire`** verb on
the resources brokers may reference.
The `SubjectAccessReview` checks the broker SPIFFE ID as a Kubernetes username
and does not set groups. The broker pod's Kubernetes ServiceAccount is not
used as the reviewed subject.

SPIRE intentionally does **not** use Kubernetes' built-in `impersonate` verb
for this check. The built-in verb has broader meaning in Kubernetes RBAC: it
can authorize native impersonation of users, groups, ServiceAccounts, and
other impersonation targets. Granting that built-in verb to broker-related
Kubernetes identities would create powerful RBAC subjects with permissions
outside SPIRE's broker authorization decision. The `impersonate-via-spire`
verb is a SPIRE-specific authorization gate checked only by this
`SubjectAccessReview`; granting it lets Kubernetes answer SPIRE's question
without granting Kubernetes-native impersonation power.

For example, with broker ID `spiffe://example.org/broker`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spire-broker-impersonation
rules:
  # This is the broker authorization decision enforced by SubjectAccessReview.
  # Use SPIRE's custom verb, not Kubernetes' built-in `impersonate` verb.
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["impersonate-via-spire"]
  - apiGroups: ["kustomize.toolkit.fluxcd.io"]
    resources: ["kustomizations"]
    verbs: ["impersonate-via-spire"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spire-broker-impersonation
subjects:
  - kind: User
    name: spiffe://example.org/broker
roleRef:
  kind: ClusterRole
  name: spire-broker-impersonation
  apiGroup: rbac.authorization.k8s.io
```

A `Role` and `RoleBinding` can be used instead when brokers should only be
allowed to authorize SPIRE broker references for namespaced resources in a
specific namespace.

## Image selector limitations

The `container-image`, `pod-image`, and `pod-init-image` selectors are derived from two fields in the Kubernetes [ContainerStatus](https://pkg.go.dev/k8s.io/api/core/v1#ContainerStatus): `Image` (typically the tag-based name, e.g. `myimage:v1.2.3`) and `ImageID` (typically the digest-based identifier, e.g. `myimage@sha256:abc...`). Both values are emitted as selectors for each container to support matching by either form.

**Tag-based image names can be inconsistent.** The `Image` field is populated by the container runtime via the [CRI API](https://github.com/kubernetes/cri-api), which does not standardize which image name to return when a single image digest is associated with multiple tags. For example, if `myimage:latest` and `myimage:v1.2.3` both refer to the same SHA256 digest, the container runtime may report either tag in the `Image` field, and the choice can vary across nodes or over time. This has been observed in multiple CRI implementations (e.g. [cri-dockerd](https://github.com/Mirantis/cri-dockerd/issues/165)).

As a result, **registration entries that rely on tag-based image selectors may produce inconsistent attestation results**. A workload deployed with `myimage:v1.2.3` could be attested with a `container-image:myimage:latest` selector (or vice versa) if both tags resolve to the same digest on that node.

**Recommendation:** For reliable workload registration, prefer using **digest-based image identifiers** (the `ImageID` form) in selectors rather than tag-based names. For example, use:

```text
k8s:container-image:docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb
```

instead of:

```text
k8s:container-image:docker.io/envoyproxy/envoy-alpine:v1.16.0
```

Tag-based selectors remain useful for human readability and for dynamic workload registration scenarios where the digest is not yet known (e.g. before an image pull is initiated). However, operators should be aware of the trade-off between readability and uniqueness, and avoid relying on tag-based image selectors in environments where multiple tags may reference the same image digest. See [#4287](https://github.com/spiffe/spire/issues/4287) for more details.

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

To enable the Kubernetes API server cache used by object-reference lookups:

```hcl
WorkloadAttestor "k8s" {
  plugin_data {
    experimental {
      api_server {
        cache {
          enabled = true
        }
      }
    }
  }
}
```

## Platform support

This plugin is only supported on Unix systems.

## Known issues

* This plugin may fail to correctly attest workloads in pods that use lifecycle hooks to alter pod start behavior. This includes Istio workloads when the `holdApplicationUntilProxyStarts` configurable is set to true. Please see [#3092](https://github.com/spiffe/spire/issues/3092) for more information. The `disable_container_selectors` configurable can be used to successfully attest workloads in this situation, albeit with reduced selector granularity (i.e. pod selectors only).

* Tag-based image selectors (`container-image`, `pod-image`, `pod-init-image`) can produce inconsistent attestation results when multiple image tags reference the same digest. The container runtime may non-deterministically report any of the associated tags, which can cause workloads to fail attestation on some nodes. Use digest-based image identifiers for reliable matching. See the [image selector limitations](#image-selector-limitations) section and [#4287](https://github.com/spiffe/spire/issues/4287) for more information.
