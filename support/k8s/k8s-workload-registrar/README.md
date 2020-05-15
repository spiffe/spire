# SPIRE Kubernetes Workload Registrar

The SPIRE Kubernetes Workload Registrar implements a Kubernetes
ValidatingAdmissionWebhook that facilitates automatic workload registration
within Kubernetes.

## Configuration

### Command Line Configuration

The registrar has the following command line flags:

| Flag         | Description                                                      | Default                       |
| ------------ | -----------------------------------------------------------------| ----------------------------- |
| `-config`    | Path on disk to the [HCL Configuration](#hcl-configuration) file | `k8s-workload-registrar.conf` |


### HCL Configuration

The configuration file is a **required** by the registrar. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                        | Type    | Required? | Description                              | Default |
| -------------------------- | --------| ---------| ----------------------------------------- | ------- |
| `log_level`                | string  | required | Log level (one of `"panic"`,`"fatal"`,`"error"`,`"warn"`, `"warning"`,`"info"`,`"debug"`,`"trace"`) | `"info"` |
| `log_path`                 | string  | optional | Path on disk to write the log | |
| `trust_domain`             | string  | required | Trust domain of the SPIRE server | |
| `server_socket_path`       | string  | required | Path to the Unix domain socket of the SPIRE server | |
| `cluster`                  | string  | required | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration. | |
| `pod_label`                | string  | optional | The pod label used for [Label Based Workload Registration](#label-based-workload-registration) | |
| `pod_annotation`           | string  | optional | The pod annotation used for [Annotation Based Workload Registration](#annotation-based-workload-registration) | |
| `mode`                     | string  | optional | How to run the registrar, either using a `"webhook"` or `"crd"`. See [Differences](#differences-between-webhook-and-crd-modes) for more details. | `"webhook"` |

The following configuration directives are specific to `"webhook"` mode:

| Key                        | Type    | Required? | Description                              | Default |
| -------------------------- | --------| ---------| ----------------------------------------- | ------- |
| `addr`                     | string  | required | Address to bind the HTTPS listener to | `":8443"` |
| `cert_path`                | string  | required | Path on disk to the PEM-encoded server TLS certificate | `"cert.pem"` |
| `key_path`                 | string  | required | Path on disk to the PEM-encoded server TLS key |  `"key.pem"` |
| `cacert_path`              | string  | required | Path on disk to the CA certificate used to verify the client (i.e. API server) | `"cacert.pem"` |
| `insecure_skip_client_verification`  | boolean | required | If true, skips client certificate verification (in which case `cacert_path` is ignored). See [Security Considerations](#security-considerations) for more details. | `false` |

The following configuration directives are specific to `"crd"` mode:

| Key                        | Type    | Required? | Description                              | Default |
| -------------------------- | --------| ---------| ----------------------------------------- | ------- |
| `add_svc_dns_name`         | bool    | optional | Enable adding service names as SAN DNS names to endpoint pods | `true` |
| `disabled_namespaces`      | []string| optional | Comma seperated list of namespaces to disable auto SVID generation for | `"kube-system"` |
| `leader_election`          | bool    | optional | Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager. | `false` |
| `metrics_bind_addr`        | string  | optional | The address the metric endpoint binds to. The special value of "0" disables metrics. | `":8080"` |
| `pod_controller`           | bool    | optional | Enable auto generation of SVIDs for new pods that are created | `true` |
| `webhook_enabled`          | bool    | optional | Enable a validating webhook to ensure CRDs are properly fomatted and there are no duplicates. Only needed if manually creating entries | `false` |
| `webhook_cert_dir`         | string  | optional | Directory for certificates when enabling validating webhook. The certificate and key must be named tls.crt and tls.key. | `"/run/spire/serving-certs"` |
| `webhook_port`             | int     | optional | The port to use for the validating webhook. | `9443` |


### Example

```
log_level = "debug"
trust_domain = "domain.test"
server_socket_path = "/run/spire/sockets/registration.sock"
cluster = "production"
```

## CRD Mode Configuration

The following configuration is required before `"crd"` mode can be used:

1. The SPIFFE ID CRD needs to be applied: `kubectl apply -f mode-crd/config/spiffeid.spiffe.io_spiffeids.yaml`
1. The appropriate ClusterRole need to be applied. `kubectl apply -f mode-crd/config/crd_role.yaml`
   * This creates a new ClusterRole named `spiffe-crd-role`
1. The new ClusterRole needs a ClusterRoleBinding to the SPIRE Server ServiceAccount. Change the name of the ServiceAccount and then: `kubectl apply -f mode-crd/config/crd_role_binding.yaml` 
   * This creates a new ClusterRoleBinding named `spiffe-crd-rolebinding`
1. If you would like to manually create CRDs, then a validating webhook is needed to prevent misconfigurations: `kubectl apply -f mode-crd/config/webhook.yaml`
   * This creates a new ValidatingWebhookConfiguration and Service, both named `k8s-workload-registrar`
   * Make sure to add your CA Bundle to the ValidatingWebhookConfiguration where it says `<INSERT BASE64 CA BUNDLE HERE>`
   * Additionally a Secret that volume mounts the certificate and key to use for the webhook. See `webhook_cert_dir` configuration option above.


### SPIFFE ID CRD Example
A sample SPIFFE ID CRD is below:

```
apiVersion: spiffeid.spiffe.io/v1beta1
kind: SpiffeID
metadata:
  name: my-spiffe-id
  namespace: my-namespace
spec:
  dnsNames:
  - my-dns-name
  selector:
    namespace: default
    podName: my-pod-name
  spiffeId: spiffe://example.org/my-spiffe-id
  parentId: spiffe://example.org/spire/server
```

The supported selectors are:
- arbitrary -- Arbitrary selectors
- containerName -- Name of the container
- containerImage -- Container image used
- namespace -- Namespace to match for this SPIFFE ID
- nodeName -- Node name to match for this SPIFFE ID
- podLabel --  Pod label name/value to match for this SPIFFE ID
- podName -- Pod name to match for this SPIFFE ID
- podUID --  Pod UID to match for this SPIFFE ID
- serviceAccount -- ServiceAccount to match for this SPIFFE ID

Note: Specifying DNS Names is optional.

## Node Registration

On startup, the registrar creates a node registration entry that groups all
PSAT attested nodes for the configured cluster. For example, if the configuration
defines the `example-cluster`, the following node registration entry would
be created and used as the parent for all workloads:

```
Entry ID      : 7f18a693-9f94-4e91-af7a-a8a61e9f4bce
SPIFFE ID     : spiffe://example.org/k8s-workload-registrar/example-cluster/node
Parent ID     : spiffe://example.org/spire/server
TTL           : default
Selector      : k8s_psat:cluster:example-cluster
```

## Workload Registration

The registrar handles pod CREATE and DELETE admission review requests to create
and delete registration entries for workloads running on those pods. The
workload registration entries are configured to run on any node in the
cluster.

There are three workload registration modes.
If you use Service Account Based, don't specify either `pod_label` or `pod_annotation`. If you use Label Based, specify only `pod_label`. If you use Annotation Based, specify only `pod_annotation`.

### Service Account Based Workload Registration

The SPIFFE ID granted to the workload is derived from the 1) service
account or 2) a configurable pod label or 3) a configurable pod annotation.

Service account derived workload registration maps the service account into a
SPIFFE ID of the form
`spiffe://<TRUSTDOMAIN>/ns/<NAMESPACE>/sa/<SERVICEACCOUNT>`. For example, if a
pod came in with the service account `blog` in the `production` namespace, the
following registration entry would be created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/ns/production/sa/blog
Parent ID     : spiffe://example.org/k8s-workload-registrar/example-cluster/node
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

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/example-workload
Parent ID     : spiffe://example.org/k8s-workload-registrar/example-cluster/node
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

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/production/example-workload
Parent ID     : spiffe://example.org/k8s-workload-registrar/example-cluster/node
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod annotation are ignored.

## Deployment

The registrar should be deployed as a container in the SPIRE server pod, since
it talks to SPIRE server via a Unix domain socket. It will need access to a
shared volume containing the socket file. The registrar will also need access
to its server keypair and the CA certificate it uses to verify clients.

The following K8S objects are required to set up the validating admission controller:
* `Service` pointing to the registrar port within the spire-server container
* `ValidatingWebhookConfiguration` configuring the registrar as a validating admission controller.

Additionally, unless you disable client authentication (`insecure_skip_client_verification`), you will need:
* `Config` with a user entry for the registrar service client containing the client certificate/key the API server should use to authenticate with the registrar.
* `AdmissionConfiguration` describing where the API server can locate the file containing the `Config`. This file is passed to the API server via the `--admission-control-config-file` flag.

For convenience, a command line utility is provided to generate authentication
material and relevant Kubernetes configuration YAML.

```
$ go run generate-config.go
.... YAML configuration dump ....
```

## Security Considerations

The registrar authenticates clients by default. This is a very important aspect
of the overall security of the registrar since the registrar can be used to
provide indirect access to the SPIRE server registration API, albeit scoped. It
is *NOT* recommended to skip client verification (via the
`insecure_skip_client_verification` configurable) unless you fully understand
the risks.

## Differences between webhook and crd modes

The main difference is that `"crd"` mode uses a SPIFFE ID custom resource definition(CRD) along with controllers, instead of a Validating Admission Webhook.

- A namespace scoped SpiffeID CRD is defined. A controller watches for create, update, delete, etc. events and creates entries on the SPIRE Server accordingly.
- An optional pod controller (`pod_controller`) watches for POD events and creates/deletes SpiffeID CRDs accordingly. The pod controller sets the pod as the owner of the SPIFFE ID CRD so it is automatically garbage collected if the POD is deleted. The pod controller adds the pod name as the first DNS name, which SPIRE adds as both a DNS SAN and the CN field on the SVID.
- An optional endpoint controller (`add_svc_dns_name`) watches for endpoint events and adds the Service Name as a DNS SAN to the SVID for all pods that are endpoints of the service. A pod can be an endpoint of multiple services and as a result can have multiple Service Names added as DNS SANs. If a service is removed, the Service Name is removed from the SVID of all endpoint Pods. The format of the DNS SAN is `<service_name>.<namespace>.svc`
- An option to disable namespaces from auto-generation (`disabled_namespaces`). By default `kube-system` is disabled for auto-generation.
- Auto generated entries are parented to the node, rather than to a cluster-wide parent.
