# Server plugin: BundlePublisher "exec"

The `exec` plugin executes the specified command giving it the current trust bundle of the server
on its stdin

The plugin accepts the following configuration options:

| Configuration     | Description                                                                                                                                                    | Required                                                               | Default                                             |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|-----------------------------------------------------|
| cmd               | Command to run                                                                                                                                                 | Yes.                                                                   |                                                     |
| format            | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details. | No.                                                                    | spiffe                                              |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Sample configuration

```hcl
    BundlePublisher "exec" {
        plugin_data {
            cmd = ["/bin/bash", "-c", "cat > /tmp/wark; scp /tmp/wark foohost:/usr/share/nginx/html/bundle.spiffe"]
        }
    }
```
