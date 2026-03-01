# KeyManager HashiCorp Vault plugin suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io),
installs HashiCorp Vault. It then asserts the following:

* SPIRE server successfully requests a key from the referenced Vault Transit Secret Engine
* Verifies that Auth Methods are configured successfully
