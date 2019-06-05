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
| `addr`                     | string  | required | Address to bind the HTTPS listener to | `":8443"` |
| `cert_path`                | string  | required | Path on disk to the PEM-encoded server TLS certificate | `"cert.pem"` |
| `key_path`                 | string  | required | Path on disk to the PEM-encoded server TLS key |  `"key.pem"` |
| `cacert_path`              | string  | required | Path on disk to the CA certificate used to verify the client (i.e. API server) | `"cacert.pem"` |
| `insecure_skip_client_verification` | boolean | required | If true, skips client certificate verification (in which case `cacert_path` is ignored) | `false` |
| `trust_domain`             | string  | required | Trust domain of the SPIRE server | |
| `server_socket_path`       | string  | required | Path to the Unix domain socket of the SPIRE server | |
| `cluster`                  | string  | required | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration. | |
| `pod_label`                | string  | optional | The pod label used for [Label Based Workload Registration](#label-based-workload-registration) | |

### Example

```
log_level = "debug"
trust_domain = "domain.test"
server_socket_path = "/run/spire/sockets/registration.sock"
cluster = "production"
```

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

There are two workload registration modes.

### Service Account Based Workload Registration

The SPIFFE ID granted to the workload is derived from the 1) service
account or 2) a configurable pod label.

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

````
$ go run generate-config.go
.... YAML configuration dump ....
```

## Security Considerations

The registrar authenticates clients by default. This is a very important aspect
of the overall security of the registrar since the registrar can be used to
provide indirectly access the SPIRE server registration API, albeit scoped. It
is *NOT* recommended to skip client verification (via the
`insecure_skip_client_verification` configurable) unless you fully understand
the risks.
