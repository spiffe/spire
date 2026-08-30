# Server plugin: UpstreamAuthority "kmip"

The `kmip` upstream authority plugin uses a
[KMIP](https://www.oasis-open.org/committees/kmip/)-compliant server (binary TTLV over
TCP, port 5696) as the signing CA. It mints intermediate X.509 CA certificates for the
SPIRE server by issuing KMIP `Certify` operations, with the CA private key never leaving
the KMIP server.

The plugin uses the [ovh/kmip-go](https://github.com/ovh/kmip-go) client library.

> **Compatibility note:** To mint a CA certificate, the plugin injects the
> `basicConstraints CA:TRUE` extension via an Eviden KMS (Cosmian)-specific vendor
> attribute (`x509-extension`, `vendor_identification="cosmian"`). KMIP servers that do
> not support this vendor attribute may reject or ignore it, in which case the issued
> certificate will lack the CA constraint and the plugin may not work with them as-is.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required | Description                                                                              | Default                 |
|----------------------|--------|----------|------------------------------------------------------------------------------------------|-------------------------|
| kmip_addr            | string | required | The TCP address of the KMIP server (e.g. `kmip.example.com:5696`).                       |                         |
| ca_key_uid           | string | required | The KMIP UniqueIdentifier of the CA private key used to sign CSRs.                       |                         |
| ca_cert_uid          | string |          | The KMIP UniqueIdentifier of the root CA certificate object; auto-discovered when empty. |                         |
| ca_cert_path         | string |          | PEM file used to verify the KMIP server TLS certificate.                                 | System certificate pool |
| client_cert_path     | string |          | PEM file of the mTLS client certificate.                                                 |                         |
| client_key_path      | string |          | PEM file of the mTLS client private key.                                                 |                         |
| insecure_skip_verify | bool   |          | Accept any KMIP server certificate (test environments only).                             | false                   |

A sample configuration:

```hcl
    UpstreamAuthority "kmip" {
        plugin_data {
            kmip_addr        = "kmip.example.com:5696"
            ca_cert_path     = "/opt/spire/conf/kmip/ca.crt"
            client_cert_path = "/opt/spire/conf/kmip/client.crt"
            client_key_path  = "/opt/spire/conf/kmip/client.key"
            ca_key_uid       = "ca-private-key-uid"
            ca_cert_uid      = "ca-cert-uid"
        }
    }
```
