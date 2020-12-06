# Kubernetes Suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io) and asserts the following:

* SPIRE server attests SPIRE agents by verifying Kubernetes Projected Service
  Account Tokens (i.e. `k8s_psat`) via the Token Review API.
* Workloads are registered via the K8S Workload Registrar and are able to
  obtain identities without the need for manually maintained registration
  entries.

## Prerequisites

```bash
# scratch test use the alpine agent for the workload
make images
make scratch-images
```

## Run Test
```bash
cd test/integration/suites/k8s-scratch
export RUNDIR=./run
mkdir -p ./run
./00-setup
./01-apply-config
./02-check-for-workload-svid
```

## Cleanup
```bash
./teardown
```
