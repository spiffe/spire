# SPIRE Kubernetes Workload Registrar

**The SPIRE Kubernetes Workload Registrar is deprecated and no longer maintained. Please migrate to the [SPIRE Controller Manager](https://github.com/spiffe/spire-controller-manager).**

The SPIRE Kubernetes Workload Registrar implements a Kubernetes
ValidatingAdmissionWebhook that facilitates automatic workload registration
within Kubernetes.

## Configuration

### Command Line Configuration

The registrar has the following command line flags:

| Flag      | Description                                                      | Default                       |
|-----------|------------------------------------------------------------------|-------------------------------|
| `-config` | Path on disk to the [HCL Configuration](#hcl-configuration) file | `k8s-workload-registrar.conf` |

### HCL Configuration

The configuration file is a **required** by the registrar. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                   | Type     | Required? | Description                                                                                                                          | Default                        |
|-----------------------|----------|-----------|--------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| `log_level`           | string   | required  | Log level (one of `"panic"`,`"fatal"`,`"error"`,`"warn"`, `"warning"`,`"info"`,`"debug"`,`"trace"`)                                  | `"info"`                       |
| `log_path`            | string   | optional  | Path on disk to write the log                                                                                                        |                                |
| `trust_domain`        | string   | required  | Trust domain of the SPIRE server                                                                                                     |                                |
| `agent_socket_path`   | string   | optional  | Path to the Unix domain socket of the SPIRE agent. Required if server_address is not a unix domain socket address.                   |                                |
| `server_address`      | string   | required  | Address of the spire server. A local socket can be specified using unix:///path/to/socket. This is not the same as the agent socket. |                                |
| `server_socket_path`  | string   | optional  | Path to the Unix domain socket of the SPIRE server, equivalent to specifying a server_address with a "unix://..." prefix             |                                |
| `cluster`             | string   | required  | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration.                     |                                |
| `pod_label`           | string   | optional  | The pod label used for [Label Based Workload Registration](#label-based-workload-registration)                                       |                                |
| `pod_annotation`      | string   | optional  | The pod annotation used for [Annotation Based Workload Registration](#annotation-based-workload-registration)                        |                                |
| `mode`                | string   | required  | How to run the registrar, either `"reconcile"` or `"crd"`. See [Differences](#differences-between-modes) for more details.           |                                |
| `disabled_namespaces` | []string | optional  | Comma separated list of namespaces to disable auto SVID generation for                                                               | `"kube-system", "kube-public"` |

The following configuration directives are specific to `"reconcile"` mode:

| Key                             | Type   | Required? | Description                                                                             | Default                 |
|---------------------------------|--------|-----------|-----------------------------------------------------------------------------------------|-------------------------|
| `leader_election`               | bool   | optional  | Enable/disable leader election. Enable if you have multiple registrar replicas running. | false                   |
| `leader_election_resource_lock` | string | optional  | Configures the type of resource to use for the leader election lock.                    | `"leases"`              |
| `metrics_addr`                  | string | optional  | Address to expose metrics on, use `0` to disable.                                       | `":8080"`               |
| `controller_name`               | string | optional  | Forms part of the spiffe IDs used for parent IDs                                        | `"spire-k8s-registrar"` |
| `add_pod_dns_names`             | bool   | optional  | Enable/disable adding k8s DNS names to pod SVIDs.                                       | false                   |
| `cluster_dns_zone`              | string | optional  | The DNS zone used for services in the k8s cluster.                                      | `"cluster.local"`       |

For CRD configuration directives see [CRD Mode Configuration](mode-crd/README.md#configuration)

### Example

```hcl
log_level = "debug"
trust_domain = "domain.test"
server_socket_path = "/tmp/spire-server/private/api.sock"
cluster = "production"
```

## Workload Registration

When running in reconcile or crd mode with `pod_controller=true` entries will be automatically created for
Pods. The available workload registration modes are:

| Registration Mode | pod_label                 | pod_annotation                 | identity_template                 | Service Account Based |
|-------------------|---------------------------|--------------------------------|-----------------------------------|-----------------------|
| `reconcile`       | as specified by pod_label | as specified by pod_annotation | _unavailable_                     | service account       |
| `crd`             | as specified by pod_label | as specified by pod_annotation | as specified by identity_template | _unavailable_         |

If using the `reconcile` mode with [Service Account Based SPIFFE IDs](#service-account-based-workload-registration), don't specify either `pod_label` or `pod_annotation`. If you use Label Based SPIFFE IDs, specify only `pod_label`. If you use Annotation Based SPIFFE IDs, specify only `pod_annotation`.

For `crd` mode, if neither `pod_label` nor `pod_annotation`
workload registration mode is selected,
`identity_template` is used with a default configuration:
`ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}`

It may take several seconds for newly created SVIDs to become available to workloads.

### Federated Entry Registration

The pod annotation `spiffe.io/federatesWith` can be used to create SPIFFE ID's that federate with other trust domains.

To specify multiple trust domains, separate them with commas.

Example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    spiffe.io/federatesWith: example.com,example.io,example.ai
  name: test
spec:
  containers:
  ...
```

### Service Account Based Workload Registration

The SPIFFE ID granted to the workload is derived from the 1) service
account or 2) a configurable pod label or 3) a configurable pod annotation.

Service account derived workload registration maps the service account into a
SPIFFE ID of the form
`spiffe://<TRUSTDOMAIN>/ns/<NAMESPACE>/sa/<SERVICEACCOUNT>`. For example, if a
pod came in with the service account `blog` in the `production` namespace, the
following registration entry would be created:

```shell
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/ns/production/sa/blog
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

### Label Based Workload Registration

Label based workload registration maps a pod label value into a SPIFFE ID of
the form `spiffe://<TRUSTDOMAIN>/<LABELVALUE>`. For example if the registrar
was configured with the `spire-workload` label and a pod came in with
`spire-workload=example-workload`, the following registration entry would be
created:

```shell
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod label are ignored.

### Annotation Based Workload Registration

Annotation based workload registration maps a pod annotation value into a SPIFFE ID of
the form `spiffe://<TRUSTDOMAIN>/<ANNOTATIONVALUE>`. By using this mode,
it is possible to freely set the SPIFFE ID path. For example if the registrar
was configured with the `spiffe.io/spiffe-id` annotation and a pod came in with
`spiffe.io/spiffe-id: production/example-workload`, the following registration entry would be
created:

```shell
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/production/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod annotation are ignored.

### Identity Template Based Workload Registration

This is specific to the `crd` mode. See [Identity Template Based Workload Registration](mode-crd/README.md#identity-template-based-workload-registration) in the `crd` mode documentation.

## Deployment

The registrar can either be deployed as standalone deployment, or as a container in the SPIRE server pod.
If it is deployed standalone then it will require manual creation of an admin registration entry which will match
the registrar deployment.

If it is deployed as a container within the SPIRE server pod then it talks to SPIRE server via a Unix domain socket. It will need access to a
shared volume containing the socket file.

### Reconcile Mode Configuration

To use reconcile mode you need to create appropriate roles and bind them to the ServiceAccount you intend to run the controller as.
An example can be found in `mode-reconcile/config/roles.yaml`, which you would apply with `kubectl apply -f mode-reconcile/config/role.yaml`

### CRD Mode Configuration

See [Quick Start for CRD Kubernetes Workload Registrar](mode-crd/README.md#quick-start)

## DNS names

Both `"reconcile"` and `"crd"` mode provide the ability to add DNS names to registration entries for pods. They
currently have different ideas about what names should be added, with `"reconcile"` adding every possible name that can
be used to access a pod (via a service or directly), and `"crd"` mode limiting itself to `<service>.<namespace>.svc`.
This functionality defaults off for `"reconcile"` mode and on for `"crd"` mode.

Warning: Some software is known to "validate" DNS and IP SANs provided in client certificates by using reverse DNS.
There is no guarantee that a client in Kubernetes will be seen to connect from an IP address with valid reverse DNS
matching one of the names generated by either of these DNS name implementation, in which case such validation will fail.
If you are intending to use X509-SVIDs to authenticate clients to such services you will need to disable adding dns names
to entries. This is known to affect etcd.

## Differences between modes

The `"reconcile"` and `"crd"` modes both make use of reconciling controllers. Both modes,
with the pod_controller enabled, have similar automated workload creation
functionality and are capable of recovering from (and cleaning up after)
failure of the registrar. Each also ensure that automatically created
entries for Pods are limited to the appropriate Nodes to prevent SVID
flooding. When used in this way, `"reconcile"` may be slightly faster to create new entries than `"crd"` mode, and requires
less configuration.

`"crd"` mode additionally provides a namespaced SpiffeID custom resource. These are used internally by the
registrar, but may also be manually created to allow creation of arbitrary Spire Entries. If you intend to manage
SpiffeID custom resources directly then it is strongly encouraged to run the controller with the `"crd"` mode's webhook
enabled.

### Platform support

This tool is only supported on Unix systems.
