# SPIRE Kubernetes Workload Registrar

The SPIRE Kubernetes Workload Registrar implements a Kubernetes
Controller that facilitates automatic workload registration
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
| `log_level`                | string  | optional | Log level (one of `"panic"`,`"fatal"`,`"error"`,`"warn"`, `"warning"`,`"info"`,`"debug"`,`"trace"`) | `"info"` |
| `log_path`                 | string  | optional | Path on disk to write the log | |
| `metrics_addr`             | string  | optional | Address to expose metrics on, use `0` to disable. | 0 |
| `agent_socket_path`        | string  | optional | Path to the Unix domain socket of the SPIRE agent. Required if server_address is not a unix domain socket address. | |
| `server_address`           | string  | required | Address of the spire server. A local socket can be specified using unix:///path/to/socket. This is not the same as the agent socket. | |
| `trust_domain`             | string  | required | Trust domain of the SPIRE server | |
| `cluster`                  | string  | required | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration. | |
| `pod_label`                | string  | optional | The pod label used for [Label Based Workload Registration](#label-based-workload-registration) | |
| `pod_annotation`           | string  | optional | The pod annotation used for [Annotation Based Workload Registration](#annotation-based-workload-registration) | |
| `controller_name`          | string  | optional | Forms part of the spiffe IDs used for parent IDs | `"spire-k8s-registrar"` |
| `leader_election`          | bool    | optional | Enable/disable leader election. Enable if you have multiple registrar replicas running. | false |
| `add_pod_dns_names`        | bool    | optional | Enable/disable adding k8s DNS names to pod SVIDs. | false |
| `cluster_dns_zone`         | string  | optional | The DNS zone used for services in the k8s cluster. | `"cluster.local"` |

### Example

```
log_level = "debug"
trust_domain = "domain.test"
agent_socket_path = "/run/spire/sockets/agent.sock"
server_address = "123.123.123.123:8081"
cluster = "production"
```

## Node Registration

The registrar creates node registration entries for each Kubernetes node within
the configured cluster. These are used as parents for workloads running on that
node. For example, if the configuration defines the `example-cluster`, the
following node registration entry would be created for a node named "foo":
	
```
Entry ID      : 7f18a693-9f94-4e91-af7a-a8a61e9f4bce
SPIFFE ID     : spiffe://example.org/spire-k8s-registrar/example-cluster/node/foo
Parent ID     : spiffe://example.org/spire/server
TTL           : default
Selector      : k8s_psat:cluster:example-cluster k8s_psat:agent_node_name:foo
```

## Workload Registration

The registrar reconciles Pods to create and delete registration
entries for workloads running in those pods. The workload registration entries
have a parent ID unique to the node on which they are scheduled.

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

The registrar should be deployed as normal kubernetes deployment. It will need access to a spire agent
socket, and will need to be issued an SVID with admin permissions on the SPIRE server. If
you do not wish to expose the SPIRE server admin API then it can talk to SPIRE server via a
Unix domain socket. In that case it will need access to a shared volume containing the socket
file.

## Migration from the webhook

The same config file can be used with the new controller, the unneeded options will be ignored.

The k8s ValidatingWebhookConfiguration will need to be removed or pods may fail admission. If you used the default
configuration this can be done with:

`kubectl validatingwebhookconfiguration delete k8s-workload-registrar-webhook`

You will also need to add additional roles to the spire-server service account to allow the registrar to reconcile
pods and nodes.  At minimum it requires the following ClusterRole rules:
```
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]
```
You will also need a Role with the following rules to enable multiple instances of the registrar to perform
leader election:
```
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["controller-leader-election-helper"]
    verbs: ["update", "get"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create"]
```
