# Kubernetes with CRD mode Suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io) and asserts the following:

* SPIRE server attests SPIRE agents by verifying Kubernetes Projected Service
  Account Tokens (i.e. `k8s_psat`) via the Token Review API.
* Workloads are registered via the K8S Workload Registrar (crd mode) and are able to
  obtain identities with expected DNS and SPIFFE ID without the need for manually maintained registration
  entries.
