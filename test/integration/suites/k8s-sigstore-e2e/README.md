# Kubernetes Sigstore Suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io) and asserts the following:

* SPIRE server attests SPIRE agents by verifying Kubernetes Projected Service
  Account Tokens (i.e. `k8s_psat`) via the Token Review API.
* Workloads using signed and unsigned images are given spiffeIds during the attestation phase based on the match with the image-signature-subject selector on the entry created for them in a specific test step.  
