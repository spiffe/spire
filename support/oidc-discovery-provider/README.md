# SPIRE OIDC Discovery Provider

The SPIRE OIDC Discovery Provider is a small helper that provides a minimal
implementation of a subset of the OIDC discovery document as related to
exposing a JSON Web Key Set (JWKS) for JSON Web Token (JWT) validation.

It provides the following endpoints:

| Verb  | Path                                | Description                               |
| ----- | ------------------------------------| ------------------------------------------|
| `GET` | `/.well-known/openid-configuration` | Returns the OIDC discovery document       |
| `GET` | `/keys`                             | Returns the JWKS for JWT validation       |

The provider by default relies on ACME to obtain TLS certificates that it uses to
serve the documents securely.

## Configuration

### Command Line Configuration

The provider has the following command line flags:

| Flag         | Description                                                      | Default                        |
| ------------ | -----------------------------------------------------------------| ------------------------------ |
| `-config`    | Path on disk to the [HCL Configuration](#hcl-configuration) file | `oidc-discovery-provider.conf` |


### HCL Configuration

The configuration file is **required** by the provider. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                  | Type    | Required?   | Description                                              | Default  |
| -------------------- | --------| ----------- | -------------------------------------------------------- | -------- |
| `acme`               | section | required[1] | Provides the ACME configuration.                         |          |
| `domain`             | string  | required    | The domain the provider is being served from.            |          |
| `listen_socket_path` | string  | required[1] | Path on disk to listen with a Unix Domain Socket.        |          |
| `log_format`         | string  | optional    | Format of the logs (either `"TEXT"` or `"JSON"`)         | `""`     |
| `log_level`          | string  | required    | Log level (one of `"error"`,`"warn"`,`"info"`,`"debug"`) | `"info"` |
| `log_path`           | string  | optional    | Path on disk to write the log.                           |          |
| `log_requests`       | bool    | optional    | If true, all HTTP requests are logged at the debug level | false    |
| `registration_api`   | section | required[2] | (Deprecated) Provides Registration API details.          |          |
| `server_api`         | section | required[2] | Provides SPIRE Server API details.                       |          |
| `workload_api`       | section | required[2] | Provides Workload API details.                           |          |

[1]: One of `acme` or `listen_socket_path` must be defined.

[2]: One of `server_api` or `workload_api` must be defined. The provider relies on one of these two APIs to obtain the public key material used to construct the JWKS document. The `registration_api` section is deprecated; the `server_api` section should be used in its place.

#### ACME Section

| Key                | Type    | Required?   | Description                               | Default |
| ------------------ | --------| ----------- | ----------------------------------------- | ------- |
| `cache_dir`        | string  | optional    | The directory used to cache the ACME-obtained credentials. Disabled if explicitly set to the empty string | `"./.acme-cache"` |
| `directory_url`    | string  | optional    | The ACME directory URL to use. Uses Let's Encrypt if unset. | `"https://acme-v01.api.letsencrypt.org/directory"` |
| `email`            | string  | required    | The email address used to register with the ACME service | |
| `tos_accepted`     | bool    | required    | Indicates explicit acceptance of the ACME service Terms of Service. Must be true. | |

#### Server API Section

| Key                | Type     | Required? | Description                              | Default |
| ------------------ | -------- | --------- | ----------------------------------------- | ------- |
| `address`          | string   | required  | SPIRE Server API gRPC target address. Only the unix name system is supported. See https://github.com/grpc/grpc/blob/master/doc/naming.md. | |
| `poll_interval`    | duration | optional  | How often to poll for changes to the public key material. | `"10s"` |

#### Workload API Section

| Key                | Type     | Required? | Description                               | Default |
| ------------------ | -------- | --------- | ----------------------------------------- | ------- |
| `socket_path`      | string   | required  | Path on disk to the Workload API Unix Domain socket. | |
| `poll_interval`    | duration | optional  | How often to poll for changes to the public key material. | `"10s"` |
| `trust_domain`     | string   | required  | Trust domain of the workload. This is used to pick the bundle out of the Workload API response. | |

#### Registration API Section (Deprecated)

| Key                | Type     | Required? | Description                              | Default |
| ------------------ | -------- | --------- | ----------------------------------------- | ------- |
| `socket_path`      | string   | required  | Path on disk to the Registration API Unix Domain socket. | |
| `poll_interval`    | duration | optional  | How often to poll for changes to the public key material. | `"10s"` |

### Examples

#### Server API

```
log_level = "debug"
domain = "mypublicdomain.test"
acme {
    cache_dir = "/some/path/on/disk/to/cache/creds"
    tos_accepted = true
}
server_api {
    address = "unix:///tmp/spire-server/private/api.sock"
}
```

#### Workload API

```
log_level = "debug"
domain = "mypublicdomain.test"
acme {
    cache_dir = "/some/path/on/disk/to/cache/creds"
    tos_accepted = true
}
workload_api {
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_domain = "domain.test"
}
```

#### Listening on a Unix Socket

The following configuration has the OIDC Discovery Provider listen for requests
on the given socket.  This can be used in conjunction with a webserver like 
Nginx, Apache, or Envoy which supports reverse proxying to a unix socket.


```
log_level = "debug"
domain = "mypublicdomain.test"
listen_socket_path = "/run/oidc-discovery-provider/server.sock"

workload_api {
    socket_path = "/tmp/spire-agent/private/api.sock"
    trust_domain = "domain.test"
}
```

A minimal Nginx configuration that proxies all traffic to the OIDC Discovery 
Provider's socket might look like this.

```
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
