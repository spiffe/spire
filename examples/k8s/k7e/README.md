# Example Kustomize Configurations

This directory contains various examples of deploying and configuring SPIRE to
Kubernetes using [kustomize](https://kustomize.io) which is part of Kubectl as
of 1.14.

+ [base_minikube_sat](base_minikube_sat) - A base configuration for SPIRE in
  minikube using the SAT attestor. This is also the base configuration from
  which all other configurations in this directory are derived.
+ [community_day_2019_may](community_day_2019_may) - This is the demo from
  SPIFFE Community Day in May, 2019.

These configurations use the bundle notifier plugin introduced in spire 0.8
(and note that currently `unstable` container images are used until 0.8 is
released). The bundle notifier replaces both the bootstrap and upstream CA.

## Using Kustomize with Kubectl

You'll want to read the documentation for
[kustomize](https://github.com/kubernetes-sigs/kustomize/tree/master/docs)
and
[kubectl](https://kubectl.docs.kubernetes.io/pages/app_management/introduction.html),
however here's a quick primer.

## Examine Resolved Configuration

To look at a fully resolved configuration (the final YAML that will be applied
by kubectl, you can use the "kustomize" argument to `kubectl` along with the
directory of the configuration to apply. For example:

```
$ kubectl kustomize base_minikube_sat
```

## Apply Configuration to Kubernetes

To apply a kustomize configuration with kubectl, use the "-k" option to the
"apply" option along with the directory of the configuration to apply:

```
$ kubectl apply -k base_minikube_sat
```
