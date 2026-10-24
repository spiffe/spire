# UpstreamAuthority Eviden KMS plugin integration suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io)
and an Eviden KMS instance (Docker). It then asserts the following:

* SPIRE server successfully signs its intermediate CA CSR via the KMS `Certify` operation
* The upstream X.509 root is returned and usable as SPIRE's trust anchor
* SVIDs are issued to workloads after CA establishment

## Configuration

The SPIRE server is configured with:

```hcl
UpstreamAuthority "kmip" {
    plugin_data {
        kmip_addr        = "kmip-server.spire-test.svc:5696"
        ca_cert_path     = "/run/spire/kmip-tls/ca.crt"
        client_cert_path = "/run/spire/kmip-tls/client.crt"
        client_key_path  = "/run/spire/kmip-tls/client.key"
        ca_key_uid       = "spire-upstream-ca-key"
    }
}
```

## Prerequisites

The root CA private key must be created in the KMS before SPIRE starts.
`01-setup-kms` handles this automatically for the integration test.
