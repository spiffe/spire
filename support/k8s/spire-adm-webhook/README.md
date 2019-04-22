# SPIRE Admission Webhook

The SPIRE Admission Webhook is a Kubernetes ValidatingAdmissionWebhook that
facilitates automatic workload registration within Kubernetes.

On startup, it creates a node registration entry that groups all PSAT attested
nodes for the given cluster, like the following:

```
Entry ID      : 7f18a693-9f94-4e91-af7a-a8a61e9f4bce
SPIFFE ID     : spiffe://example.org/node
Parent ID     : spiffe://example.org/spire/server
TTL           : default
Selector      : k8s_psat:cluster:example-cluster
```

The webhook handles pod CREATE and DELETE admission review requests to create
and delete registration entries for workloads running on those pods. The
workload registration entries are configured to run on any node in the
cluster. The SPIFFE ID granted to the workload is derived from the 1) service
account or 2) a configurable pod label.

Service account derived workload registration maps the service account into a
SPIFFE ID of the form
`spiffe://<TRUSTDOMAIN>/ns/<NAMESPACE>/sa/<SERVICEACCOUNT>`. For example, if a
pod came in with the service account `blog` in the `production` namespace, the
following registration entry would be created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/ns/production/sa/blog
Parent ID     : spiffe://example.org/node
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pod label derived workload registration maps a configurable pod label value
into a SPIFFE ID of the form `spiffe://<TRUSTDOMAIN>/<LABELVALUE>`. For example
if the webhook was configured with the `spire-workload` label and a pod came in
with `spire-workload=example-workload`, the following registration entry would
be created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/example-workload
Parent ID     : spiffe://example.org/node
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```
