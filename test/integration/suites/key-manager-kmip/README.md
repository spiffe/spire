# KeyManager Eviden KMS plugin integration suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io)
and an Eviden KMS instance (Docker). It then asserts the following:

* SPIRE server successfully creates asymmetric key pairs in Eviden KMS via the KMIP 2.1 protocol
* SPIRE server successfully signs data using keys stored in Eviden KMS
* Keys survive SPIRE server restarts (key recovery via KMIP `Locate`)
* mTLS authentication to the KMS is exercised

## Prerequisites

* `kind` CLI
* `kubectl` CLI
* Docker with the `cosmian/kms` image available (or Docker Hub access)
* `openssl` CLI

## Configuration

The SPIRE server is configured with:

```hcl
KeyManager "kmip" {
    plugin_data {
        kmip_addr        = "kmip-server.spire-test.svc:5696"
        ca_cert_path     = "/run/spire/kmip-tls/ca.crt"
        client_cert_path = "/run/spire/kmip-tls/client.crt"
        client_key_path  = "/run/spire/kmip-tls/client.key"
        server_id        = "spire-server-test"
    }
}
```

## Running manually

```bash
./00-setup-kind
./01-setup-kms
./02-deploy-spire-and-verify-auth
./teardown
```
