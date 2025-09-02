# SPIRE OIDC Discovery Provider

The SPIRE OIDC Discovery Provider is a small helper that provides a minimal
implementation of a subset of the OIDC discovery document as related to
exposing a JSON Web Key Set (JWKS) for JSON Web Token (JWT) validation.

It provides the following endpoints:

| Verb  | Path                                | Description                                                                                                             |
|-------|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `GET` | `/.well-known/openid-configuration` | Returns the OIDC discovery document                                                                                     |
| `GET` | `/keys`                             | Returns the JWKS for JWT validation                                                                                     |
| `GET` | `/ready`                            | Returns http.OK (200) as soon as requests can be served. (disabled by default)                                          |
| `GET` | `/live`                             | Returns http.OK (200) as soon as a keyset is available, otherwise http.InternalServerError (500). (disabled by default) |

The endpoints can be moved to a different prefix by way of the `server_path_prefix` option. For example, setting server_path_prefix to `/instance/1` will make
the OIDC discovery document served at `/instance/1/.well-known/openid-configuration` and keys at `/instance/1/keys`

The provider by default relies on ACME to obtain TLS certificates that it uses to
serve the documents securely.

## Configuration

### Command Line Configuration

The provider has the following command line flags:

| Flag      | Description                                                      | Default                        |
|-----------|------------------------------------------------------------------|--------------------------------|
| `-config` | Path on disk to the [HCL Configuration](#hcl-configuration) file | `oidc-discovery-provider.conf` |

### HCL Configuration

The configuration file is **required** by the provider. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                     | Type    | Required?          | Description                                                            | Default  |
|-------------------------|---------|--------------------|------------------------------------------------------------------------|----------|
| `acme`                  | section | required[1]        | Provides the ACME configuration.                                       |          |
| `serving_cert_file`     | section | required\[1\]\[4\] | Provides the serving certificate configuration.                        |          |
| `allow_insecure_scheme` | bool    | optional\[3\]      | Serves OIDC configuration response with HTTP url.                      | `false`  |
| `domains`               | strings | required           | One or more domains the provider is being served from.                 |          |
| `experimental`          | section | optional           | The experimental options that are subject to change or removal.        |          |
| `insecure_addr`         | string  | optional\[3\]      | Exposes the service on http.                                           |          |
| `set_key_use`           | bool    | optional           | If true, the `use` parameter on JWKs will be set to `sig`.             | `false`  |
| `listen_socket_path`    | string  | required\[1\]\[3\] | Path on disk to listen with a Unix Domain Socket. Unix platforms only. |          |
| `log_format`            | string  | optional           | Format of the logs (either `"TEXT"` or `"JSON"`)                       | `""`     |
| `log_level`             | string  | required           | Log level (one of `"error"`,`"warn"`,`"info"`,`"debug"`)               | `"info"` |
| `log_path`              | string  | optional           | Path on disk to write the log.                                         |          |
| `log_requests`          | bool    | optional           | If true, all HTTP requests are logged at the debug level               | `false`  |
| `server_api`            | section | required\[2\]      | Provides SPIRE Server API details.                                     |          |
| `workload_api`          | section | required\[2\]      | Provides Workload API details.                                         |          |
| `file`                  | section | required\[2\]      | Provides File details.                                                 |          |
| `health_checks`         | section | optional           | Enable and configure health check endpoints                            |          |
| `jwt_issuer`            | string  | optional           | Specifies the issuer for the OIDC provider configuration request       |          |
| `jwks_uri`              | string  | optional           | Specifies the JWKS URI returned in the discovery document              |          |
| `server_path_prefix`    | string  | optional           | If specified, all endpoints listened to will be prefixed by this value | `"/"`    |

| experimental             | Type   | Required?          | Description                                          | Default |
|--------------------------|--------|--------------------|------------------------------------------------------|---------|
| `listen_named_pipe_name` | string | required\[1\]\[3\] | Pipe name to listen with a named pipe. Windows only. |         |

<!-- markdownlint-configure-file { "MD053": false } -->

#### Considerations for Unix platforms

[1]: One of `acme`, `serving_cert_file` or `listen_socket_path` must be defined.

[3]: The `allow_insecure_scheme` should only be used in a local development environment for testing purposes. It only works in conjunction with `insecure_addr` or `listen_socket_path`.

#### Considerations for Windows platforms

[1]: One of `acme`, `serving_cert_file` or `listen_named_pipe_name` must be defined.

[3]: The `allow_insecure_scheme` should only be used in a local development environment for testing purposes. It only works in conjunction with `insecure_addr` or `listen_named_pipe_name`.

#### Considerations for all platforms

[2]: One of `server_api`, `workload_api`, or `file` must be defined. The provider relies on one of these APIs to obtain the public key material used to construct the JWKS document.

The `domains` configurable contains the list of domains the provider is
expected to be served from. If a request is received from a domain other than
one in the list (as determined by the Host or X-Forwarded-Host header), it
will be rejected. Likewise, when ACME is used, the `domains` list contains the
allowed domains for which certificates will be obtained. The TLS handshake
will terminate if another domain is requested.

[4]: SPIRE OIDC Discovery provider monitors and reloads the files provided in the `serving_cert_file` configuration at runtime.

#### ACME Section

| Key             | Type   | Required? | Description                                                                                               | Default                                            |
|-----------------|--------|-----------|-----------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| `cache_dir`     | string | optional  | The directory used to cache the ACME-obtained credentials. Disabled if explicitly set to the empty string | `"./.acme-cache"`                                  |
| `directory_url` | string | optional  | The ACME directory URL to use. Uses Let's Encrypt if unset.                                               | `"https://acme-v01.api.letsencrypt.org/directory"` |
| `email`         | string | required  | The email address used to register with the ACME service                                                  |                                                    |
| `tos_accepted`  | bool   | required  | Indicates explicit acceptance of the ACME service Terms of Service. Must be true.                         |                                                    |

#### Serving Certificate Section

| Key                  | Type     | Required? | Description                                                        | Default  |
|----------------------|----------|-----------|--------------------------------------------------------------------|----------|
| `cert_file_path`     | string   | required  | The certificate file path, the file must contain PEM encoded data. |          |
| `key_file_path`      | string   | required  | The private key file path, the file must contain PEM encoded data. |          |
| `file_sync_interval` | duration | optional  | Controls how frequently the service polls the files for changes.   | 1 minute |
| `addr`               | string   | optional  | Exposes the service on the given address.                          | :443     |

#### Server API Section

| Key             | Type     | Required? | Description                                                                                                                                                      | Default |
|-----------------|----------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `address`       | string   | required  | SPIRE Server API gRPC target address. Only the unix name system is supported. See <https://github.com/grpc/grpc/blob/master/doc/naming.md>. Unix platforms only. |         |
| `experimental`  | section  | optional  | The experimental options that are subject to change or removal.                                                                                                  |         |
| `poll_interval` | duration | optional  | How often to poll for changes to the public key material.                                                                                                        | `"10s"` |

| experimental      | Type   | Required? | Description                                                 | Default |
|:------------------|--------|-----------|-------------------------------------------------------------|---------|
| `named_pipe_name` | string | required  | Pipe name of the SPIRE Server API named pipe. Windows only. |         |

#### Workload API Section

| Key             | Type     | Required? | Description                                                                                     | Default |
|-----------------|----------|-----------|-------------------------------------------------------------------------------------------------|---------|
| `experimental`  | section  | optional  | The experimental options that are subject to change or removal.                                 |         |
| `socket_path`   | string   | required  | Path on disk to the Workload API Unix Domain socket. Unix platforms only.                       |         |
| `poll_interval` | duration | optional  | How often to poll for changes to the public key material.                                       | `"10s"` |
| `trust_domain`  | string   | required  | Trust domain of the workload. This is used to pick the bundle out of the Workload API response. |         |

| experimental      | Description                                             | Default |
|:------------------|---------------------------------------------------------|---------|
| `named_pipe_name` | Pipe name of the Workload API named pipe. Windows only. |         |

#### File Section

| Key             | Type     | Required? | Description                                               | Default |
|-----------------|----------|-----------|-----------------------------------------------------------|---------|
| `path`          | string   | required  | Path on disk to the spiffe formatted trust bundle to use. |         |
| `poll_interval` | duration | optional  | How often to poll for changes to the public key material. | `"10s"` |

#### Health Checks Section

Health checks are enabled by adding `health_checks {}` to the configuration.
The health checks endpoints are hosted on a dedicated listener on localhost.

- The "ready" state is determined by the availability of keys fetched via the workload/server API. If the keys where fetched successfully but can't be fetched anymore (e.g. workload or server API can't be reached), the server is still determined ready for the threshold interval.
- The "live" state is either determined by the availability of keys fetched via the workload/server API or the threshold interval after the server started serving requests. If the keys where fetched successfully but can't be fetched anymore (e.g. workload/server API can't be reached), the server is still determined live for the threshold interval.

The threshold interval is currently set to 5 times the workload/server APIs poll interval, but at least 3 minutes.
Both states respond with a 200 OK status code for success or 500 Internal Server Error for failure.

| Key          | Type   | Required? | Description                         | Default    |
|--------------|--------|-----------|-------------------------------------|------------|
| `bind_port`  | string | optional  | override default listener bind port | `"8008"`   |
| `ready_path` | string | optional  | override default ready path         | `"/ready"` |
| `live_path`  | string | optional  | override default live path          | `"/live"`  |

### Examples (Unix platforms)

#### Server API and ACME

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
acme {
    cache_dir = "/some/path/on/disk/to/cache/creds"
    email = "email@domain.test"
    tos_accepted = true
}
server_api {
    address = "unix:///tmp/spire-server/private/api.sock"
}
```

#### Workload API and ACME

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
acme {
    cache_dir = "/some/path/on/disk/to/cache/creds"
    email = "email@domain.test"
    tos_accepted = true
}
workload_api {
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_domain = "domain.test"
}
```

#### Server API and Serving Certificate

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
serving_cert_file {
 cert_file_path = "/some/path/on/disk/to/cert.pem"
 key_file_path = "/some/path/on/disk/to/key.pem"
}
server_api {
    address = "unix:///tmp/spire-server/private/api.sock"
}
```

#### Workload API and Serving Certificate

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
serving_cert_file {
 cert_file_path = "/some/path/on/disk/to/cert.pem"
 key_file_path = "/some/path/on/disk/to/key.pem"
}
workload_api {
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_domain = "domain.test"
}
```

#### Listening on a Unix Socket

The following configuration has the OIDC Discovery Provider listen for requests
on the given socket. This can be used in conjunction with a webserver like
Nginx, Apache, or Envoy which supports reverse proxying to a unix socket.

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
listen_socket_path = "/run/oidc-discovery-provider/server.sock"

workload_api {
    socket_path = "/tmp/spire-agent/private/api.sock"
    trust_domain = "domain.test"
}
```

A minimal Nginx configuration that proxies all traffic to the OIDC Discovery
Provider's socket might look like this.

```nginx
daemon off;
 events {}
 http {
   access_log /dev/stdout;
   upstream oidc {
     server unix:/run/oidc-discovery-provider/server.sock;
   }
   server {
     # ... Any TLS and listening config you may need
     location / {
       proxy_pass http://oidc;
     }
   }
 }
```

### Examples (Windows)

#### Server API and ACME

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
acme {
    cache_dir = "c:\\some\\path\\on\\disk\\to\\cache\\creds"
    email = "email@domain.test"
    tos_accepted = true
}
server_api {
    experimental {
        named_pipe_name = "\\spire-server\\private\\api"
    }
}
```

#### Workload API and ACME

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
acme {
    cache_dir = "c:\\some\\path\\on\\disk\\to\\cache\\creds"
    email = "email@domain.test"
    tos_accepted = true
}
workload_api {
    experimental {
        named_pipe_name = "\\spire-agent\\public\\api"
    }
    trust_domain = "domain.test"
}
```

#### Server API and Serving Certificate

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
serving_cert_file {
    cert_file_path = "c:\\some\\path\\on\\disk\\to\\cert.pem"
    key_file_path = "c:\\some\\path\\on\\disk\\to\\key.pem"
}
server_api {
    experimental {
        named_pipe_name = "\\spire-server\\private\\api"
    }
}
```

#### Workload API and Serving Certificate

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
serving_cert_file {
 cert_file_path = "c:\\some\\path\\on\\disk\\to\\cert.pem"
 key_file_path = "c:\\some\\path\\on\\disk\\to\\key.pem"
}
workload_api {
    experimental {
        named_pipe_name = "\\spire-agent\\public\\api"
    }
    trust_domain = "domain.test"
}
```

#### Listening on a Named Pipe

The following configuration has the OIDC Discovery Provider listen for requests
on the given named pipe. This can be used in conjunction with a webserver that
supports reverse proxying to a named pipe.

```hcl
log_level = "debug"
domains = ["mypublicdomain.test"]
experimental {
    listen_named_pipe_name = "oidc-discovery-provider"
}

workload_api {
    experimental {
        named_pipe_name = "\\spire-agent\\public\\api"
    }
    trust_domain = "domain.test"
}
```
