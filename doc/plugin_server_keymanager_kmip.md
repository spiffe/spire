# Server plugin: KeyManager "kmip"

The `kmip` key manager plugin stores private keys in any
[KMIP](https://www.oasis-open.org/committees/kmip/)-compliant server, speaking the
binary TTLV/TCP transport (port 5696), and uses them to sign SVIDs. The private key
material never leaves the KMIP server.

The plugin uses the [ovh/kmip-go](https://github.com/ovh/kmip-go) client library.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required  | Description                                                                     | Default                 |
|----------------------|--------|-----------|---------------------------------------------------------------------------------|-------------------------|
| kmip_addr            | string | required  | The TCP address of the KMIP server (e.g. `kmip.example.com:5696`).              |                         |
| server_id_value      | string | required¹ | Stable identifier for this SPIRE server instance, used to tag and recover keys. |                         |
| server_id_file       | string | required¹ | Path to a file containing the server identifier; created if it does not exist.  |                         |
| ca_cert_path         | string |           | CA certificate file used to verify the KMIP server TLS certificate.             | System certificate pool |
| client_cert_path     | string |           | mTLS client certificate file; must be set together with `client_key_path`.      |                         |
| client_key_path      | string |           | mTLS client private key file; must be set together with `client_cert_path`.     |                         |
| insecure_skip_verify | bool   |           | Accept any KMIP server certificate (test environments only).                    | false                   |
| stale_key_threshold  | string |           | Go duration before an unrefreshed key is treated as stale and reclaimed.        | `336h` (2 weeks)        |

¹ Exactly one of `server_id_value` or `server_id_file` must be set.

Client certificate authentication is optional at the plugin level. If both
`client_cert_path` and `client_key_path` are unset, the plugin connects without
presenting a client certificate and relies on server-authenticated TLS only. In
production, KMIP servers commonly require mTLS client authentication for
authentication and authorization; whether a client certificate is required is
enforced by the KMIP server's own configuration, not by this plugin.

### Server instance identification

The plugin tags every key pair it creates with four standard KMIP `Name` attributes:
`spire-server-id:<server_id>`, `spire-trust-domain:<trust_domain>`,
`spire-key-id:<key_id>` and `spire-key-type:<type>`. The trust-domain name exists for
operator clarity when a KMIP server is shared across multiple trust domains.
On startup, the plugin recovers the keys it previously managed by issuing a KMIP
`Locate` filtered on `spire-server-id:<server_id>`. The server identifier must therefore be
stable across restarts and unique per SPIRE server instance that shares the same KMIP
server. It is provided with either `server_id_value` (inline) or `server_id_file` (a path
whose content is used, and generated as a UUID when the file does not exist).

### Key lifecycle

Key pairs are created in the KMIP `Pre-Active` state and are activated (`Activate`)
before being used for signing. The plugin exports the public key using the transparent
key format and converts it to PKIX. Each key pair is created with SPIRE KMIP `Name`
attributes, including `spire-last-update:<unix_timestamp>`.

The plugin runs a keep-alive task every six hours that refreshes the
`spire-last-update` value on keys it is actively managing. A separate reclamation
task runs every 48 hours, locates keys tagged for this SPIRE server instance, and
destroys any key pair whose `spire-last-update` value is older than
`stale_key_threshold`, which defaults to two weeks. This reclaims keys left
behind after a crash, after a server instance stops refreshing them, or after a
key rotation leaves an older replacement candidate no longer tracked.

Operators should account for the configured staleness window during long
maintenance periods: if a SPIRE server instance is offline long enough that its
keys are not refreshed for longer than `stale_key_threshold`, a later
reclamation sweep can permanently destroy them, and the server will generate new
keys when it starts again.

When a key is replaced by a new key for the same key ID, the previous key pair is
left in KMIP intentionally and simply stops receiving `spire-last-update`
refreshes. That gives operators a recovery window until the key naturally ages
past `stale_key_threshold`, at which point the same reclamation path revokes and
destroys it. During reclamation, the plugin first revokes the key (`Revoke` with
a non-compromise reason, moving it to the `Deactivated` state) and then destroys
it (`Destroy`), following the KMIP lifecycle requirement that an object be
`Deactivated` before it can be `Destroyed`.

A sample configuration:

```hcl
    KeyManager "kmip" {
        plugin_data {
            kmip_addr        = "kmip.example.com:5696"
            ca_cert_path     = "/opt/spire/conf/kmip/ca.crt"
            client_cert_path = "/opt/spire/conf/kmip/client.crt"
            client_key_path  = "/opt/spire/conf/kmip/client.key"
            server_id_value  = "spire-server"
            stale_key_threshold = "336h"
        }
    }
```
