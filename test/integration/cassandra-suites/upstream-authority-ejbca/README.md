# Upstream Authority ejbca Suite

## Description

This suite sets up a single node Kubernetes cluster using [Kind](https://kind.sigs.k8s.io), deploys and configures EJBCA Community, and then asserts the following:

1. SPIRE Server successfully requests an intermediate CA from EJBCA.
2. Verifies that workload x509s have been signed by that intermediate CA, and that EJBCA is the root of trust.
