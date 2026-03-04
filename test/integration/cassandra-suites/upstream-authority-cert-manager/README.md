# Upstream Authority cert-manager Suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io),
installs cert-manager and a self-signed CA Issuer. It then asserts the
following:

* SPIRE server successfully requests an intermediate CA from the referenced
    cert-manager Issuer
* Verifies that obtained identities have been signed by that intermediate CA,
    and the cert-manager Issuer is the root of trust
* Verifies that the SPIRE server will delete stale CertificateRequests that it
    is responsible for
