# Server plugin: KeyManager "kmip"

The `kmip` key manager plugin stores private keys in any
[KMIP](https://www.oasis-open.org/committees/kmip/)-compliant server, speaking the
binary TTLV/TCP transport (port 5696), and uses them to sign SVIDs. The private key
material never leaves the KMIP server.

The plugin uses the [ovh/kmip-go](https://github.com/ovh/kmip-go) client library.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required  | Description                                                                                      | Default                 |
|----------------------|--------|-----------|--------------------------------------------------------------------------------------------------|-------------------------|
| kmip_addr            | string | required  | The TCP address of the KMIP server (e.g. `kmip.example.com:5696`).                               |                         |
| server_id_value      | string | required¹ | Stable identifier for this SPIRE server instance, used to tag and recover keys.                  |                         |
| server_id_file       | string | required¹ | Path to a file containing the server identifier; created if it does not exist.                   |                         |
| ca_cert_path         | string |           | CA certificate file used to verify the KMIP server TLS certificate.                              | System certificate pool |
| client_cert_path     | string |           | mTLS client certificate file; must be set together with `client_key_path`.                       |                         |
| client_key_path      | string |           | mTLS client private key file; must be set together with `client_cert_path`.                      |                         |
| insecure_skip_verify | bool   |           | Accept any KMIP server certificate (test environments only).                                     | false                   |
| stale_key_threshold  | string |           | Go duration before an unrefreshed key is treated as stale and reclaimed; must be at least `24h`. | `336h` (2 weeks)        |

¹ Exactly one of `server_id_value` or `server_id_file` must be set.

Client certificate authentication is optional at the plugin level. If both
`client_cert_path` and `client_key_path` are unset, the plugin connects without
presenting a client certificate and relies on server-authenticated TLS only. In
production, KMIP servers commonly require mTLS client authentication for
authentication and authorization; whether a client certificate is required is
enforced by the KMIP server's own configuration, not by this plugin.

### Server instance identification

The plugin stores its metadata on every key pair it creates as KMIP custom
attributes, set in the `Create Key Pair` request:

| Attribute              | Value                                                            |
|------------------------|------------------------------------------------------------------|
| `x-spire-server-id`    | The configured server identifier                                 |
| `x-spire-trust-domain` | The trust domain of the SPIRE server                             |
| `x-spire-key-id`       | The SPIRE key ID                                                 |
| `x-spire-key-type`     | The SPIRE key type, e.g. `EC_P256` or `RSA_2048`                 |
| `x-spire-last-update`  | Unix timestamp of the last keep-alive refresh                    |
| `x-spire-active`       | `true` on the key currently in use for its SPIRE key ID          |

On startup, the plugin recovers the keys it previously managed. It issues a
paginated KMIP `Locate` for private key objects filtered on object type,
`x-spire-server-id` and `x-spire-trust-domain`, so keys owned by other servers or
applications are not inspected. It then reads the `x-spire-*` custom attributes of
each result and re-checks the server ID and trust domain, in case the KMIP server
does not apply custom-attribute filters. Keys with missing or unparseable metadata
are skipped with a warning. The server identifier
must therefore be stable across restarts and unique per SPIRE server instance that
shares the same KMIP server. It is provided with either `server_id_value` (inline)
or `server_id_file` (a path whose content is used, and generated as a UUID when the
file does not exist).

Because SPIRE reuses key IDs across rotations, several key objects may carry the
same `x-spire-key-id`. During recovery the plugin selects the single key whose
`x-spire-active` is `true`; if none or more than one is marked active, it selects
the one with the newest `x-spire-last-update`, and logs a warning.

### Key lifecycle

Key pairs are created in the KMIP `Pre-Active` state and are activated (`Activate`)
before being used for signing. The plugin exports the public key using the transparent
key format and converts it to PKIX. A new key is created with `x-spire-active` set to
`true`; once it is active, the plugin sets `x-spire-active` to `false` on the key it
replaces for the same key ID.

The plugin refreshes `x-spire-last-update` on the private keys it is actively
managing once at startup and then every six hours. A separate reclamation task
runs every 48 hours, locates all private keys visible to the KMIP client, and
disposes of any key pair in the same trust domain whose `x-spire-last-update`
value is older than `stale_key_threshold`, which defaults to two weeks and must
be at least 24 hours. Keys without the `x-spire-trust-domain` or
`x-spire-last-update` attributes are ignored. The minimum threshold protects
against reclaiming a key that is still in use but has not yet gone through a
keep-alive refresh cycle. This reclaims keys left behind after a crash, after a
server instance stops refreshing them, after a server instance is permanently
removed, or after a key rotation leaves an older key no longer tracked.

Operators should account for the configured staleness window during long
maintenance periods: if a SPIRE server instance is offline long enough that its
keys are not refreshed for longer than `stale_key_threshold`, a later
reclamation sweep by any server in the same trust domain can permanently
destroy them, and the server will generate new keys when it starts again.

When a key is replaced by a new key for the same key ID, the previous key pair is
left in KMIP intentionally and simply stops receiving `x-spire-last-update`
refreshes. That gives operators a recovery window until the key naturally ages
past `stale_key_threshold`, at which point the reclamation task disposes of it.
Disposal destroys the linked public key and then the private key, choosing the
path by lifecycle state: an `Active` object is first revoked (`Revoke` with a
non-compromise reason, moving it to the `Deactivated` state) and then destroyed
(`Destroy`), following the KMIP requirement that an object be `Deactivated`
before it can be `Destroyed`; objects already in a non-active state are
destroyed directly.

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
