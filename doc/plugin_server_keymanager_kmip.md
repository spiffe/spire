# Server plugin: KeyManager "kmip"

The `kmip` key manager plugin stores private keys in any
[KMIP](https://www.oasis-open.org/committees/kmip/)-compliant server, speaking the
binary TTLV/TCP transport (port 5696), and uses them to sign SVIDs. The private key
material never leaves the KMIP server.

The plugin uses the [ovh/kmip-go](https://github.com/ovh/kmip-go) client library.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required | Description                                                                                   | Default                 |
|----------------------|--------|----------|-----------------------------------------------------------------------------------------------|-------------------------|
| kmip_addr            | string | required | The TCP address of the KMIP server (e.g. `kmip.example.com:5696`).                            |                         |
| server_id            | string | required | Stable identifier for this SPIRE server instance, used to tag and recover keys.               |                         |
| ca_cert_path         | string |          | CA certificate(s) used to verify the KMIP server TLS certificate (inline PEM or a file path). | System certificate pool |
| client_cert_path     | string |          | mTLS client certificate file.                                                                 |                         |
| client_key_path      | string |          | mTLS client private key file.                                                                 |                         |
| insecure_skip_verify | bool   |          | Accept any KMIP server certificate (test environments only).                                  | false                   |

### Server instance identification

The plugin tags every key pair it creates with three standard KMIP `Name` attributes:
`spire-server-id:<server_id>`, `spire-key-id:<key_id>` and `spire-key-type:<type>`.
On startup, the plugin recovers the keys it previously managed by issuing a KMIP
`Locate` filtered on `spire-server-id:<server_id>`. The `server_id` must therefore be
stable across restarts and unique per SPIRE server instance that shares the same KMIP
server.

### Key lifecycle

Key pairs are created in the KMIP `Pre-Active` state and are activated (`Activate`)
before being used for signing. The plugin exports the public key using the transparent
key format and converts it to PKIX.

A sample configuration:

```hcl
    KeyManager "kmip" {
        plugin_data {
            kmip_addr        = "kmip.example.com:5696"
            ca_cert_path     = "/opt/spire/conf/kmip/ca.crt"
            client_cert_path = "/opt/spire/conf/kmip/client.crt"
            client_key_path  = "/opt/spire/conf/kmip/client.key"
            server_id        = "spire-server"
        }
    }
```
