# SPIRE Kubernetes Workload Registrar (CRD Mode)

The CRD mode of the SPIRE Kubernetes Workload Registrar uses a Kuberntes Custom Resource Definition (CRD) to integrate SPIRE and Kubernetes.
This enables auto and manual generation of SPIFFE IDs from with Kubenretes and the `kubectl` CLI.

## Benefits of CRD Kubernetes Workload Registrar

There are mutiple modes of the Kubernetes Workload Registrar. The benefits of the CRD mode when compared to other modes are:

* **`kubectl` integration**: Using a CRD, SPIRE is fully intergrated with Kubernetes. You can view and create SPIFFE IDs directly using `kubectl`, without having to shell into the the SPIRE server.
* **Fully event-driven design**: Using the Kubernetes CRD system, the CRD mode Kubernetes Workload Registrar is fully event-driven to minimze resource usage.
* **Standards-based solution**: CRDs are the standard way to extend Kubernetes, with many resources online, such as [kubebuilder](https://book.kubebuilder.io/), discussing the approach. The CRD Kubernetes Worklaod Registrar follows all standards and best practices to ensure it is maintainable.

## Configuration

### Command Line Configuration

The registrar has the following command line flags:

| Flag         | Description                                                      | Default                       |
| ------------ | -----------------------------------------------------------------| ----------------------------- |
| `-config`    | Path on disk to the [HCL Configuration](#hcl-configuration) file | `k8s-workload-registrar.conf` |


### HCL Configuration

The configuration file is a **required** by the registrar. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                        | Type     | Required? | Description                              | Default |
| -------------------------- | ---------| ---------| ----------------------------------------- | ------- |
| `add_svc_dns_name`         | bool     | optional | Enable adding service names as SAN DNS names to endpoint pods | `true` |
| `agent_socket_path`        | string   | optional | Path to the Unix domain socket of the SPIRE agent. Required if server_address is not a unix domain socket address. | |
| `cluster`                  | string   | required | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration. | |
| `context`                  | map[string]string | optional | The map of key/value pairs of arbitrary string parameters to be used by `identity_template` | |
| `disabled_namespaces`      | []string | optional | Comma seperated list of namespaces to disable auto SVID generation for | `"kube-system", "kube-public"` |
| `identity_template`        | string   | optional | The template for custom [Identity Template Based Workload Registration](#identity-template-based-workload-registration) | `ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}` |
| `identity_template_label`  | string   | optional | Pod label for selecting pods that get SVIDs whose SPIFFE IDs are defined by `identity_template` format. If not set, applies to all the pods when `identity_template` is set  |  |
| `leader_election`          | bool     | optional | Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager. | `false` |
| `log_level`                | string   | required | Log level (one of `"panic"`,`"fatal"`,`"error"`,`"warn"`, `"warning"`,`"info"`,`"debug"`,`"trace"`) | `"info"` |
| `log_path`                 | string   | optional | Path on disk to write the log | |
| `metrics_bind_addr`        | string   | optional | The address the metric endpoint binds to. The special value of "0" disables metrics. | `":8080"` |
| `mode`                     | string   | optional | Must be set to `"crd"`. | `"webhook"` |
| `pod_annotation`           | string   | optional | The pod annotation used for [Annotation Based Workload Registration](#annotation-based-workload-registration) | |
| `pod_controller`           | bool     | optional | Enable auto generation of SVIDs for new pods that are created | `true` |
| `pod_label`                | string   | optional | The pod label used for [Label Based Workload Registration](#label-based-workload-registration) | |
| `server_address`           | string   | required | Address of the spire server. A local socket can be specified using unix:///path/to/socket. This is not the same as the agent socket. | |
| `server_socket_path`       | string   | optional | Path to the Unix domain socket of the SPIRE server, equivalent to specifying a server_address with a "unix://..." prefix | |
| `trust_domain`             | string   | required | Trust domain of the SPIRE server | |
| `webhook_enabled`          | bool     | optional | Enable a validating webhook to ensure CRDs are properly fomatted and there are no duplicates. | `false` |
| `webhook_port`             | int      | optional | The port to use for the validating webhook. | `9443` |
| `webhook_service_name`     | string   | optional | The name of the Kubernetes Service being used for the webhook. | `"k8s-workload-registrar"` |

## Quick Start

This quick start sets up the SPIRE Server, SPIRE Agent, and CRD Kubernetes Workload Registrar.

1. Deploy SPIRE Server, Kubernetes Workload Registrar, SPIRE Agent, and CRD. SPIRE Server and Kubernetes Workload Registrar will be deployed in the same Pod.
   ```
   kubectl apply -f config/spiffeid.spiffe.io_spiffeids.yaml \
                 -f config/spire-server-registrar.yaml \
                 -f config/spire-agent.yaml
   ```

1. Verify the deployment succeeded.
   ```
   $ kubectl get pods -n spire
   NAME                READY   STATUS    RESTARTS   AGE
   spire-agent-4wdxx   1/1     Running   0          5m59s
   spire-agent-hmxxf   1/1     Running   0          5m59s
   spire-agent-vgtdp   1/1     Running   0          5m59s
   spire-server-0      2/2     Running   0          58s
   ```

   The `spire-server-0` Pod should have two containers running in it.

## Examples

Here are some examples of things you can do once the CRD Kubernetes Workload Registrar is deployed.

### Create a SpiffeID Resource using kubectl

1. Create a SpiffeID resource.
   ```
   kubectl apply -f samples/test_spiffeid.yaml
   ```

1. Check that the SpiffeID  resource was created.
   ```
   $ kubectl get spiffeids
   NAME               AGE
   my-test-spiffeid   85s
   $ kubectl get spiffeid my-test-spiffeid -o yaml
   apiVersion: spiffeid.spiffe.io/v1beta1
   kind: SpiffeID
   metadata:
     annotations:
       kubectl.kubernetes.io/last-applied-configuration: |
         {"apiVersion":"spiffeid.spiffe.io/v1beta1","kind":"SpiffeID","metadata":{"annotations":{},"name":"my-test-spiffeid","namespace":"default"},"spec":{"parentId":"spiffe://example.org/spire/server","selector":{"namespace":"default","podName":"my-test-pod"},"spiffeId":"spiffe://example.org/test"}}
     creationTimestamp: "2020-10-22T21:09:10Z"
     finalizers:
     - finalizers.spiffeid.spiffe.io
     generation: 1
     name: my-test-spiffeid
     namespace: default
     resourceVersion: "132384095"
     selfLink: /apis/spiffeid.spiffe.io/v1beta1/namespaces/default/spiffeids/my-test-spiffeid
     uid: 810f228d-de22-4e32-b684-4f42c0cb15ea
   spec:
     parentId: spiffe://example.org/spire/server
     selector:
       namespace: default
       podName: my-test-pod
     spiffeId: spiffe://example.org/test
   status:
     entryId: ad49519e-37a1-4de5-a661-c091d3652b9c
   ```

1. Verify the SPIFFE ID was created on the SPIRE Server
   ```
   $ kubectl exec spire-server-0 -n spire -c spire-server -- ./bin/spire-server entry show -spiffeID spiffe://example.org/test
   Found 1 entry
   Entry ID      : ad49519e-37a1-4de5-a661-c091d3652b9c
   SPIFFE ID     : spiffe://example.org/test
   Parent ID     : spiffe://example.org/spire/server
   Revision      : 0
   TTL           : default
   Selector      : k8s:ns:default
   Selector      : k8s:pod-name:my-test-pod
   ```

1. Delete the SpiffeID resource, the corresponding entry on the SPIRE Server will be removed.
   ```
   kubectl delete -f samples/test_spiffeid.yaml
   ```

### Attempt to Deploy an Invalid SpiffeID Resource

1. Apply deploy an invalid SpiffeID.
   ```
   $ kubectl apply -f test_spiffeid_bad.yaml
   Error from server (spec.Selector.Namespace must match namespace of resource): error when creating "test_spiffeid_bad.yaml": admission webhook "k8s-workload-registrar.nginx-mesh.svc" denied the request: spec.Selector.Namespace must match namespace of resource
   ```

   The Validating Webhook rejects the attempt to create an invalid resource.

### Auto-generate SPIFFE IDs

To test auto-generation of SPIFFE IDs add the following annotation to a Pod Spec and the apply it. A recommended format for the SPIFFE ID is `ns/<namespace>/id/<id>`.

   ```
   spiffe.io/spiffe-id: <SPIFFE ID>
   ```

We can test this using the NGINX example deployment:

1. Deploy the example NGINX deployment
   ```
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/application/simple_deployment.yaml
   ```

1. Add the annotation to the Deployment Template. This will reroll the deployment
   ```
   kubectl patch deployment nginx-deployment -p '{"spec":{"template":{"metadata":{"annotations":{"spiffe.io/spiffe-id": "ns/default/id/nginx"}}}}}'
   ```

1. Verify the SpiffeID resource was created. The name of the SpiffeID resource will be the same as the name of the Pod.
   ```
   $ kubectl get spiffeids
   NAME                                AGE
   nginx-deployment-7ff586d896-kvwzl   4s
   $ kubectl get spiffeids nginx-deployment-7ff586d896-kvwzl -o yaml
   apiVersion: spiffeid.spiffe.io/v1beta1
   kind: SpiffeID
   metadata:
     creationTimestamp: "2020-10-26T22:48:55Z"
     finalizers:
     - finalizers.spiffeid.spiffe.io
     generation: 1
     labels:
       podUid: e271fbf6-faff-42e3-bd40-3718829cca0a
     name: nginx-deployment-7ff586d896-kvwzl
     namespace: default
     ownerReferences:
     - apiVersion: v1
       blockOwnerDeletion: false
       controller: true
       kind: Pod
       name: nginx-deployment-7ff586d896-kvwzl
       uid: e271fbf6-faff-42e3-bd40-3718829cca0a
     resourceVersion: "133768304"
     selfLink: /apis/spiffeid.spiffe.io/v1beta1/namespaces/default/spiffeids/nginx-deployment-7ff586d896-kvwzl
     uid: 89d51335-aebc-4df0-afd2-cce0d8d7b562
   spec:
     dnsNames:
     - nginx-deployment-7ff586d896-kvwzl
     parentId: spiffe://example.org/k8s-workload-registrar/demo-cluster/node/gke-fmemon-cluster-default-pool-0729ba70-563y
     selector:
       namespace: default
       nodeName: gke-fmemon-cluster-default-pool-0729ba70-563y
       podUid: e271fbf6-faff-42e3-bd40-3718829cca0a
     spiffeId: spiffe://example.org/ns/default/id/nginx
   status:
     entryId: e87b1f27-871a-4755-86fd-0debe10362d5
   ```

1. Delete the NGINX deployment, this will automatically delete the SpiffeID resource
   ```
   kubectl delete -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/application/simple_deployment.yaml
   ```

## Deleting the Quick Start

1. Delete the CRD. This needs to be done before remove the Kubernetes Workload Registrar to give the finalizers a chance to complete.
   ```
   kubectl delete -f config/spiffeid.spiffe.io_spiffeids.yaml
   ```

1. Delete the remaining previously applied yaml files.
   ```
   kubectl delete -f config/spire-server-registrar.yaml \
                  -f config/spire-agent.yaml
   ```

## Workload Registration

When running with `pod_controller=true` entries will be automatically created for
Pods. There are three workload registration modes. The default is Identity Template Based. If you want Label Based, specify only `pod_label`. If you want Annotation Based,
specify only `pod_annotation`. Only one mode can be used.

The SPIFFE ID granted to the workload is derived from the 1) identity template or 2) a configurable pod label or 3) a configurable pod annotation.

It may take several seconds for newly created SVIDs to become available to workloads.

### Identity Template Based Workload Registration

Identity template based workload registration provides a way to customize the format of SPIFFE IDs. The identity format is scoped to a cluster.
The template formatter is using Golang
[text/template](https://pkg.go.dev/text/template) conventions,
and it can reference arbitrary values provided in the `context` map of strings
in addition to the following Pod-specific arguments:
* Pod.Name
* Pod.UID
* Pod.Namespace
* Pod.ServiceAccount
* Pod.Hostname
* Pod.NodeName

For example if the registrar was configured with the following:
```
identity_template = "region/{{.Context.Region}}/cluster/{{.Context.ClusterName}}/sa/{{.Pod.ServiceAccount}}/pod_name/{{.Pod.pod_name}}"
context {
  Region = "US-NORTH"
  ClusterName = "MYCLUSTER"
}
```
and the _example-workload_ pod was deployed in _production_ namespace and _myserviceacct_ service account, the following registration entry would be created:
```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/region/US-NORTH/cluster/MYCLUSTER/sa/myserviceacct/pod_name/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

If `identity_template_label` is defined in the registrar configuration:

```
identity_template_label = "enable_identity_template"
```

only pods with the same label set to `true` would get identity SVID.

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    enable_identity_template: true
spec:
  containers:
  ...
```
Pods that don't contain the pod label are ignored.

If `identity_template_label` is empty or omitted, all the pods will receive the identity.

### Label Based Workload Registration

Label based workload registration maps a pod label value into a SPIFFE ID of
the form `spiffe://<TRUSTDOMAIN>/<LABELVALUE>`. For example if the registrar
was configured with the `spire-workload` label and a pod came in with
`spire-workload=example-workload`, the following registration entry would be
created:

```
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

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/production/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod annotation are ignored.

### Service Account Based Workload Registration (deprecated)

The default SPIFFE ID created with [Identity Template Based Workload Registration](#identity-template-based-workload-registration) is of the form
`spiffe://<TRUSTDOMAIN>/ns/<NAMESPACE>/sa/<SERVICEACCOUNT>`, so this method is no longer needed.

### Federated Entry Registration

The pod annotatation `spiffe.io/federatesWith` can be used to create SPIFFE ID's that federate with other trust domains.

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

## How it Works

Everything starts with the SpiffeID CRD ([yaml](config/spiffeid.spiffe.io_spiffeids.yaml), [golang](api/spiffeid/v1beta1/spiffeid_types.go)). The CRD is a namespace scoped resource. The CRD mirrors an entry on the SPIRE server, so when a custom resource is created a corresponding entry is created on the SPIRE server and the EntryID is saved in the SpiffeID custom resource. When the custom resource is deleted the corresponding entry on the SPIRE server is deleted.

Entries can be created manually and automatically. For automatic generation, entries are created and deleted in response to pods being created and deleted. See [Workload Registration](../README.md#workload-registration) for more information on automatic generation of entries.

### Finalizers

[Finalizers](https://book.kubebuilder.io/reference/using-finalizers.html) are added to all SpiffeID resources, manual or automatically created. This ensures that entries on the SPIRE Server are properly cleaned up when a SpiffeID resource is deleted by blocking deletion of the resource until the SPIRE Server entry is first deleted. This important for the scenario where the the Kubernetes Workload Registrar is down when a SpiffeID resource is deleted.

This has the potential side effect of blocking deletion of a namespace until all the SpiffeID resources in that namespace are first deleted.

### Validating Webhook

A Validating Webhook is used to ensure SpiffeID resources are properly formatted and performs the following checks:

* If DNS names are present they are properly formatted and don't contain disallowed characters such as a '/'.
* That the SPIFFE and Parent Ids both begin with `spiffe://`.
* The namespace selector is populated and matches the metadata.namespace of the custom resource.
* There are no duplicates, SpiffeID resources with different metadata.name's but identical Selector+SpiffeID+ParentID set.

The certificates for the webhook are generated by the SPIRE Server and managed by the Kubernetes Workload Registrar.

## SPIFFE ID Custom Resource Example
An example SPIFFE ID custom resource is below:

```
apiVersion: spiffeid.spiffe.io/v1beta1
kind: SpiffeID
metadata:
  name: my-spiffe-id
  namespace: my-namespace
spec:
  dnsNames:
  - my-dns-name
  federatesWith:
  - example-third-party.org
  selector:
    namespace: my-namespace
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

Notes: 
* Specifying DNS Names is optional
* The metadata.namespace and selector.namespace must match

## CRD Security Considerations
It is imperative to only grant trusted users access to manually create SpiffeID custom resources. Users with access have the ability to issue any SpiffeID
to any pod in the namespace.

If allowing users to manually create SpiffeID custom resources it is important to use the Validating Webhook.  The Validating Webhook ensures that
registration entries created have a namespace selector that matches the namespace the resource was created in.  This ensures that the manually created
entries can only be consumed by workloads within that namespace.
