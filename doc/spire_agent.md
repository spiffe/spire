# SPIRE Agent Configuration Reference

This document is a configuration reference for SPIRE Agent. It includes information about plugin types, built-in plugins, the agent configuration file, plugin configuration, and command line options for `spire-agent` commands.

## Plugin types

| Type             | Description                                                                                                                    |
|------------------|--------------------------------------------------------------------------------------------------------------------------------|
| KeyManager       | Generates and stores the agent's private key. Useful for binding keys to hardware, etc.                                        |
| NodeAttestor     | Gathers information used to attest the agent's identity to the server. Generally paired with a server plugin of the same type. |
| WorkloadAttestor | Introspects a workload to determine its properties, generating a set of selectors associated with it.                          |
| SVIDStore        | Stores X509-SVIDs (Private key, leaf certificate and intermediates if any), bundle, and federated bundles into a trust store.  |

## Built-in plugins

| Type             | Name                                                                    | Description                                                                                                                                      |
|------------------|-------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| KeyManager       | [disk](/doc/plugin_agent_keymanager_disk.md)                            | A key manager which writes the private key to disk                                                                                               |
| KeyManager       | [memory](/doc/plugin_agent_keymanager_memory.md)                        | An in-memory key manager which does not persist private keys (must re-attest after restarts)                                                     |
| NodeAttestor     | [aws_iid](/doc/plugin_agent_nodeattestor_aws_iid.md)                    | A node attestor which attests agent identity using an AWS Instance Identity Document                                                             |
| NodeAttestor     | [azure_msi](/doc/plugin_agent_nodeattestor_azure_msi.md)                | A node attestor which attests agent identity using an Azure MSI token                                                                            |
| NodeAttestor     | [gcp_iit](/doc/plugin_agent_nodeattestor_gcp_iit.md)                    | A node attestor which attests agent identity using a GCP Instance Identity Token                                                                 |
| NodeAttestor     | [join_token](/doc/plugin_agent_nodeattestor_jointoken.md)               | A node attestor which uses a server-generated join token                                                                                         |
| NodeAttestor     | [k8s_sat](/doc/plugin_agent_nodeattestor_k8s_sat.md) (deprecated)       | A node attestor which attests agent identity using a Kubernetes Service Account token                                                            |
| NodeAttestor     | [k8s_psat](/doc/plugin_agent_nodeattestor_k8s_psat.md)                  | A node attestor which attests agent identity using a Kubernetes Projected Service Account token                                                  |
| NodeAttestor     | [sshpop](/doc/plugin_agent_nodeattestor_sshpop.md)                      | A node attestor which attests agent identity using an existing ssh certificate                                                                   |
| NodeAttestor     | [x509pop](/doc/plugin_agent_nodeattestor_x509pop.md)                    | A node attestor which attests agent identity using an existing X.509 certificate                                                                 |
| WorkloadAttestor | [docker](/doc/plugin_agent_workloadattestor_docker.md)                  | A workload attestor which allows selectors based on docker constructs such `label` and `image_id`                                                |
| WorkloadAttestor | [k8s](/doc/plugin_agent_workloadattestor_k8s.md)                        | A workload attestor which allows selectors based on Kubernetes constructs such `ns` (namespace) and `sa` (service account)                       |
| WorkloadAttestor | [unix](/doc/plugin_agent_workloadattestor_unix.md)                      | A workload attestor which generates unix-based selectors like `uid` and `gid`                                                                    |
| WorkloadAttestor | [systemd](/doc/plugin_agent_workloadattestor_systemd.md)                | A workload attestor which generates selectors based on systemd unit properties such as `Id` and `FragmentPath`                                   |
| SVIDStore        | [aws_secretsmanager](/doc/plugin_agent_svidstore_aws_secretsmanager.md) | An SVIDstore which stores secrets in the AWS secrets manager with the resulting X509-SVIDs of the entries that the agent is entitled to.         |
| SVIDStore        | [gcp_secretmanager](/doc/plugin_agent_svidstore_gcp_secretmanager.md)   | An SVIDStore which stores secrets in the Google Cloud Secret Manager with the resulting X509-SVIDs of the entries that the agent is entitled to. |

## Agent configuration file

The following table outlines the configuration options for SPIRE agent. These may be set in a top-level `agent { ... }` section of the configuration file. Most options have a corresponding CLI flag which, if set, takes precedence over values defined in the file.

SPIRE configuration files may be represented in either HCL or JSON. Please see the [sample configuration file](#sample-configuration-file) section for a complete example.

If the -expandEnv flag is passed to SPIRE, `$VARIABLE` or `${VARIABLE}` style environment variables are expanded before parsing.
This may be useful for templating configuration files, for example across different trust domains, or for inserting secrets like join tokens.

| Configuration                     | Description                                                                                                                                                                                                                                       | Default                          |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| `admin_socket_path`               | Location to bind the admin API socket (disabled as default)                                                                                                                                                                                       |                                  |
| `allow_unauthenticated_verifiers` | Allow agent to release trust bundles to unauthenticated verifiers                                                                                                                                                                                 | false                            |
| `allowed_foreign_jwt_claims`      | List of trusted claims to be returned when validating foreign JWTSVIDs                                                                                                                                                                            |                                  |
| `authorized_delegates`            | A SPIFFE ID list of the authorized delegates. See [Delegated Identity API](#delegated-identity-api) for more information                                                                                                                          |                                  |
| `data_dir`                        | A directory the agent can use for its runtime data                                                                                                                                                                                                | $PWD                             |
| `experimental`                    | The experimental options that are subject to change or removal (see below)                                                                                                                                                                        |                                  |
| `insecure_bootstrap`              | If true, the agent bootstraps without verifying the server's identity                                                                                                                                                                             | false                            |
| `retry_bootstrap`                 | If true, the agent retries bootstrap with backoff                                                                                                                                                                                                 | false                            |
| `join_token`                      | An optional token which has been generated by the SPIRE server                                                                                                                                                                                    |                                  |
| `log_file`                        | File to write logs to                                                                                                                                                                                                                             |                                  |
| `log_level`                       | Sets the logging level &lt;DEBUG&vert;INFO&vert;WARN&vert;ERROR&gt;                                                                                                                                                                               | INFO                             |
| `log_format`                      | Format of logs, &lt;text&vert;json&gt;                                                                                                                                                                                                            | Text                             |
| `log_source_location`             | If true, logs include source file, line number, and method name fields (adds a bit of runtime cost)                                                                                                                                               | false                            |
| `profiling_enabled`               | If true, enables a [net/http/pprof](https://pkg.go.dev/net/http/pprof) endpoint                                                                                                                                                                   | false                            |
| `profiling_freq`                  | Frequency of dumping profiling data to disk. Only enabled when `profiling_enabled` is `true` and `profiling_freq` > 0.                                                                                                                            |                                  |
| `profiling_names`                 | List of profile names that will be dumped to disk on each profiling tick, see [Profiling Names](#profiling-names)                                                                                                                                 |                                  |
| `profiling_port`                  | Port number of the [net/http/pprof](https://pkg.go.dev/net/http/pprof) endpoint. Only used when `profiling_enabled` is `true`.                                                                                                                    |                                  |
| `server_address`                  | DNS name or IP address of the SPIRE server                                                                                                                                                                                                        |                                  |
| `server_port`                     | Port number of the SPIRE server                                                                                                                                                                                                                   |                                  |
| `socket_path`                     | Location to bind the SPIRE Agent API socket (Unix only)                                                                                                                                                                                           | /tmp/spire-agent/public/api.sock |
| `sds`                             | Optional SDS configuration section                                                                                                                                                                                                                |                                  |
| `trust_bundle_path`               | Path to the SPIRE server CA bundle                                                                                                                                                                                                                |                                  |
| `trust_bundle_url`                | URL to download the initial SPIRE server trust bundle                                                                                                                                                                                             |                                  |
| `trust_bundle_format`             | Format of the initial trust bundle, pem or spiffe                                                                                                                                                                                                 | pem                              |
| `trust_domain`                    | The trust domain that this agent belongs to (should be no more than 255 characters)                                                                                                                                                               |                                  |
| `workload_x509_svid_key_type`     | The workload X509 SVID key type &lt;rsa-2048&vert;ec-p256&gt;                                                                                                                                                                                     | ec-p256                          |
| `availability_target`             | The minimum amount of time desired to gracefully handle SPIRE Server or Agent downtime. This configurable influences how aggressively X509 SVIDs should be rotated. If set, must be at least 24h. See [Availability Target](#availability-target) |                                  |
| `x509_svid_cache_max_size`        | Soft limit of max number of X509-SVIDs that would be stored in LRU cache                                                                                                                                                                          | 1000                             |
| `jwt_svid_cache_max_size`         | Hard limit of max number of JWT-SVIDs that would be stored in LRU cache                                                                                                                                                                           | 1000                             |

| experimental                  | Description                                                                          | Default                 |
|:------------------------------|--------------------------------------------------------------------------------------|-------------------------|
| `named_pipe_name`             | Pipe name to bind the SPIRE Agent API named pipe (Windows only)                      | \spire-agent\public\api |
| `sync_interval`               | Sync interval with SPIRE server with exponential backoff                             | 5 sec                   |
| `use_sync_authorized_entries` | Use SyncAuthorizedEntries API for periodically synchronization of authorized entries | false                   |
| `require_pq_kem`              | Require use of a post-quantum-safe key exchange method for TLS handshakes            | false                   |

### Initial trust bundle configuration

The agent needs an initial trust bundle in order to connect securely to the SPIRE server. There are three options:

1. If the `trust_bundle_path` option is used, the agent will read the initial trust bundle from the file at that path. You need to copy or share the file before starting the SPIRE agent.
2. If the `trust_bundle_url` option is used, the agent will read the initial trust bundle from the specified URL. **The URL must start with `https://` for security, and the server must have a valid certificate (verified with the system trust store).** This can be used to rapidly deploy SPIRE agents without having to manually share a file. Keep in mind the contents of the URL need to be kept up to date.
3. If the `insecure_bootstrap` option is set to `true`, then the agent will not use an initial trust bundle. It will connect to the SPIRE server without authenticating it. This is not a secure configuration, because a man-in-the-middle attacker could control the SPIRE infrastructure. It is included because it is a useful option for testing and development.

Only one of these three options may be set at a time.

### SDS Configuration

| Configuration                    | Description                                                                                                                                                                         | Default |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `default_svid_name`              | The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS                                                                                                   | default |
| `default_bundle_name`            | The Validation Context resource name to use for the default X.509 bundle with Envoy SDS                                                                                             | ROOTCA  |
| `default_all_bundles_name`       | The Validation Context resource name to use for all bundles (including federated) with Envoy SDS                                                                                    | ALL     |
| `disable_spiffe_cert_validation` | Disable Envoy SDS custom validation                                                                                                                                                 | false   |

### Profiling Names

These are the available profiles that can be set in the `profiling_names` configuration value:

- `goroutine`
- `threadcreate`
- `heap`
- `block`
- `mutex`
- `trace`
- `cpu`

### Availability Target

_Note: The `availability_target` only affects the agent SVIDs and workload X509-SVIDs, but not JWT-SVIDs._

If the `availability_target` is set, the agent will rotate an X509 SVID when its remaining lifetime reaches the `availability_target`.

To guarantee the `availability_target`, grace period (`SVID lifetime - availability_target`) must be at least 12h.
If not satisfied, the agent will rotate the SVID by the default rotation strategy (1/2 of lifetime).

## Plugin configuration

The agent configuration file also contains the configuration for the agent plugins.
Plugin configurations are under the `plugins { ... }` section, which has the following format:

```hcl
plugins {
    pluginType "pluginName" {
        ...
        plugin configuration options here
        ...
    }
}
```

The following configuration options are available to configure a plugin:

| Configuration    | Description                                                                            |
|------------------|----------------------------------------------------------------------------------------|
| plugin_cmd       | Path to the plugin implementation binary (optional, not needed for built-ins)          |
| plugin_checksum  | An optional sha256 of the plugin binary  (optional, not needed for built-ins)          |
| enabled          | Enable or disable the plugin (enabled by default)                                      |
| plugin_data      | Plugin-specific data (mutually exclusive with `plugin_data_file`)                      |
| plugin_data_file | Path to a file containing plugin-specific data (mutually exclusive with `plugin_data`) |

Please see the [built-in plugins](#built-in-plugins) section below for information on plugins that are available out-of-the-box.

### Examples

#### Built-in Plugin with Static Configuration

```hcl
plugins {
    SomeType "some_plugin" {
        plugin_data = {
            option1 = "foo"
            option2 = 3
        }
    }
}
```

#### External Plugin with Dynamic Configuration

In the `agent.conf`, declare the plugin using the `plugin_data_file` option to source the plugin configuration from file.

```hcl
plugins {
    SomeType "some_plugin" {
        plugin_cmd = "./path/to/plugin"
        plugin_checksum = "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83"
        plugin_data_file = "some_plugin.conf"
    }
}
```

And then in `some_plugin.conf` you place the plugin configuration:

```hcl
option1 = "foo"
option2 = 3
```

### Reconfiguring plugins (Posix only)

Plugins that use dynamic configuration sources (i.e. `plugin_data_file`) can be reconfigured at runtime by sending a `SIGUSR1` signal to SPIRE Agent. This is true for both built-in and external plugins.

SPIRE Agent, upon receipt of the signal, does the following:

1. Reloads the plugin data
2. Compares the plugin data to the previous data
3. If changed, the plugin is reconfigured with the new data

## Telemetry configuration

Please see the [Telemetry Configuration](./telemetry_config.md) guide for more information about configuring SPIRE Agent to emit telemetry.

## Health check configuration

The agent can expose additional endpoint that can be used for health checking. It is enabled by setting `listener_enabled = true`. Currently, it exposes 2 paths: one for liveness (is agent up) and one for readiness (is agent ready to serve requests). By default, health checking endpoint will listen on localhost:80, unless configured otherwise.

```hcl
health_checks {
        listener_enabled = true
        bind_address = "localhost"
        bind_port = "8080"
        live_path = "/live"
        ready_path = "/ready"
}
```

## Command line options

### `spire-agent run`

All the configuration file above options have identical command-line counterparts. In addition,
the following flags are available:

| Command                          | Action                                                                              | Default               |
|----------------------------------|-------------------------------------------------------------------------------------|-----------------------|
| `-allowUnauthenticatedVerifiers` | Allow agent to release trust bundles to unauthenticated verifiers                   |                       |
| `-config`                        | Path to a SPIRE config file                                                         | conf/agent/agent.conf |
| `-dataDir`                       | A directory the agent can use for its runtime data                                  |                       |
| `-expandEnv`                     | Expand environment $VARIABLES in the config file                                    |                       |
| `-joinToken`                     | An optional token which has been generated by the SPIRE server                      |                       |
| `-logFile`                       | File to write logs to                                                               |                       |
| `-logFormat`                     | Format of logs, &lt;text&vert;json&gt;                                              |                       |
| `-logLevel`                      | DEBUG, INFO, WARN or ERROR                                                          |                       |
| `-serverAddress`                 | IP address or DNS name of the SPIRE server                                          |                       |
| `-serverPort`                    | Port number of the SPIRE server                                                     |                       |
| `-socketPath`                    | Location to bind the workload API socket                                            |                       |
| `-trustBundle`                   | Path to the SPIRE server CA bundle                                                  |                       |
| `-trustBundleUrl`                | URL to download the SPIRE server CA bundle                                          |                       |
| `-trustDomain`                   | The trust domain that this agent belongs to (should be no more than 255 characters) |                       |

#### Running SPIRE Agent as a Windows service

On Windows platform, SPIRE Agent can optionally be run as a Windows service. When running as a Windows service, the only command supported is the `run` command.

_Note: SPIRE does not automatically create the service in the system, it must be created by the user.
When starting the service, all the arguments to execute SPIRE Agent with the `run` command must be passed as service arguments._

##### Example to create the SPIRE Agent Windows service

```bash
> sc.exe create spire-agent binpath=c:\spire\bin\spire-agent.exe
```

##### Example to run the SPIRE Agent Windows service

```bash
> sc.exe start spire-agent run -config c:\spire\conf\agent\agent.conf
```

### `spire-agent api fetch`

Calls the workload API to fetch an X509-SVID. This command is aliased to `spire-agent api fetch x509`.

| Command       | Action                                | Default                          |
|---------------|---------------------------------------|----------------------------------|
| `-silent`     | Suppress stdout                       |                                  |
| `-socketPath` | Path to the SPIRE Agent API socket    | /tmp/spire-agent/public/api.sock |
| `-timeout`    | Time to wait for a response           | 1s                               |
| `-write`      | Write SVID data to the specified path |                                  |

### `spire-agent api fetch jwt`

Calls the workload API to fetch a JWT-SVID.

| Command       | Action                                              | Default                          |
|---------------|-----------------------------------------------------|----------------------------------|
| `-audience`   | A comma separated list of audience values           |                                  |
| `-socketPath` | Path to the SPIRE Agent API socket                  | /tmp/spire-agent/public/api.sock |
| `-spiffeID`   | The SPIFFE ID of the JWT being requested (optional) |                                  |
| `-timeout`    | Time to wait for a response                         | 1s                               |

### `spire-agent api fetch x509`

Calls the workload API to fetch a x.509-SVID.

| Command       | Action                                | Default                          |
|---------------|---------------------------------------|----------------------------------|
| `-silent`     | Suppress stdout                       |                                  |
| `-socketPath` | Path to the SPIRE Agent API socket    | /tmp/spire-agent/public/api.sock |
| `-timeout`    | Time to wait for a response           | 1s                               |
| `-write`      | Write SVID data to the specified path |                                  |

### `spire-agent api validate jwt`

Calls the workload API to validate the supplied JWT-SVID.

| Command       | Action                                    | Default                          |
|---------------|-------------------------------------------|----------------------------------|
| `-audience`   | A comma separated list of audience values |                                  |
| `-socketPath` | Path to the SPIRE Agent API socket        | /tmp/spire-agent/public/api.sock |
| `-svid`       | The JWT-SVID to be validated              |                                  |
| `-timeout`    | Time to wait for a response               | 1s                               |

### `spire-agent api watch`

Attaches to the workload API and watches for X509-SVID updates, printing details when updates are received.

| Command       | Action                             | Default                          |
|---------------|------------------------------------|----------------------------------|
| `-socketPath` | Path to the SPIRE Agent API socket | /tmp/spire-agent/public/api.sock |

### `spire-agent healthcheck`

Checks SPIRE agent's health.

| Command       | Action                                | Default                          |
|:--------------|:--------------------------------------|:---------------------------------|
| `-shallow`    | Perform a less stringent health check |                                  |
| `-socketPath` | Path to the SPIRE Agent API socket    | /tmp/spire-agent/public/api.sock |
| `-verbose`    | Print verbose information             |                                  |

### `spire-agent validate`

Validates a SPIRE agent configuration file.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-config`     | Path to a SPIRE agent configuration file                           | agent.conf     |
| `-expandEnv`  | Expand environment $VARIABLES in the config file                   | false          |

## Sample configuration file

This section includes a sample configuration file for formatting and syntax reference

```hcl
agent {
    trust_domain = "example.org"
    trust_bundle_path = "/opt/spire/conf/initial_bundle.crt"

    data_dir = "/opt/spire/.data"
    log_level = "DEBUG"
    server_address = "spire-server"
    server_port = "8081"
    socket_path ="/tmp/spire-agent/public/api.sock"
}

telemetry {
    Prometheus {
        port = 1234
    }
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {
        }
    }
    KeyManager "disk" {
        plugin_data {
            directory = "/opt/spire/.data"
        }
    }
    WorkloadAttestor "k8s" {
        plugin_data {
            kubelet_read_only_port = "10255"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {
        }
    }
}
```

## Delegated Identity API

The Delegated Identity API allows an authorized (i.e. delegated) workload to obtain SVIDs and bundles on behalf of workloads that cannot be attested by SPIRE Agent directly.

The Delegated Identity API is served over the SPIRE Agent's admin API endpoint.

Note that this explicitly and by-design grants the authorized delegate workload the ability to impersonate any of the other workloads it can obtain SVIDs for. Any workload authorized to use the
Delegated Identity API becomes a "trusted delegate" of the SPIRE Agent, and may impersonate and act on behalf of all workload SVIDs it obtains from the SPIRE Agent.

The trusted delegate workload itself is attested by the SPIRE Agent first, and the delegate's SPIFFE ID is checked against an allowlist of authorized delegates.

Once these requirements are met, the trusted delegate workload can obtain SVIDS for any workloads in the scope of the SPIRE Agent instance it is interacting with.

There are two ways the trusted delegate workload can request SVIDs for other workloads from the SPIRE Agent:

1. By attesting the other workload itself, building a set of selectors, and then providing SPIRE Agent those selectors over the Delegated Identity API.
  In this approach, the trusted delegate workload is entirely responsible for attesting the other workload and building the attested selectors.
  When those selectors are presented to the SPIRE Agent, the SPIRE Agent will simply return SVIDs for any workload registration entries that match the provided selectors.
  No other checks or attestations will be performed by the SPIRE Agent.

1. By obtaining a PID for the other workload, and providing that PID to the SPIRE Agent over the Delegated Identity API.
   In this approach, the SPIRE Agent will do attestation for the provided PID, build the attested selectors, and return SVIDs for any workload registration entries that match the selectors the SPIRE Agent attested from that PID.
   This differs from the previous approach in that the SPIRE Agent itself (not the trusted delegate) handles the attestation of the other workload.
   On most platforms PIDs are not stable identifiers, so the trusted delegate workload **must** ensure that the PID it provides to the SPIRE Agent
   via the Delegated Identity API for attestation is not recycled between the time a trusted delegate makes an Delegate Identity API request, and obtains a Delegate Identity API response.
   How this is accomplished is platform-dependent and the responsibility of the trusted delegate (e.g. by using pidfds on Linux).
   Attestation results obtained via the Delegated Identity API for a PID are valid until the process referred to by the PID terminates, or is re-attested - whichever comes first.

To enable the Delegated Identity API, configure the admin API endpoint address and the list of SPIFFE IDs for authorized delegates. For example:

Unix systems:

```hcl
agent {
    trust_domain = "example.org"
    ...
    admin_socket_path = "/tmp/spire-agent/private/admin.sock"
    authorized_delegates = [
        "spiffe://example.org/authorized_client1",
        "spiffe://example.org/authorized_client2",
    ]
}
```

Windows:

```hcl
agent {
    trust_domain = "example.org"
    ...
    experimental {
        admin_named_pipe_name = "\\spire-agent\\private\\admin"
    }
    authorized_delegates = [
        "spiffe://example.org/authorized_client1",
        "spiffe://example.org/authorized_client2",
    ]
}
```

## Envoy SDS Support

SPIRE agent has support for the [Envoy](https://envoyproxy.io) [Secret Discovery Service](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret) (SDS).
SDS is served over the same Unix domain socket as the Workload API. Envoy processes connecting to SDS are attested as workloads.

[`tlsv3.TlsCertificate`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlscertificate)
resources containing X509-SVIDs can be fetched using the SPIFFE ID of the workload as the resource name
(e.g. `spiffe://example.org/database`). Alternatively, if the default name "default" is used, the `tlsv3.TlsCertificate`
containing the default X509-SVID for the workload (i.e. Envoy) is fetched.
The default name is configurable (see `default_svid_name` under [SDS Configuration](#sds-configuration)).

[`tlsv3.CertificateValidationContext`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-certificatevalidationcontext)
resources containing trusted CA certificates can be fetched using the SPIFFE ID
of the desired trust domain as the resource name (e.g. `spiffe://example.org`).
In addition, two other special resource names are available. The first, which
defaults to "ROOTCA", provides the CA certificates for the trust domain the
agent belongs to. The second, which defaults to "ALL", returns the trusted CA
certificates for both the trust domain the agent belongs to as well as any
federated trust domains applicable to the Envoy workload.  The default names
for these resource names are configurable via the `default_bundle_name` and
`default_all_bundles_name`, respectively. The "ALL" resource name requires
support for the [SPIFFE Certificate Validator](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.proto)
extension, which is only available starting with Envoy 1.18.
The default name is configurable (see `default_all_bundles_name` under [SDS Configuration](#sds-configuration).

The [SPIFFE Certificate Validator](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.proto) configures Envoy to perform SPIFFE authentication. The validation context returned by SPIRE Agent contains this extension by default. However, if standard X.509 chain validation is desired, SPIRE Agent can be configured to omit the extension. The default behavior can be changed by configuring `disable_spiffe_cert_validation` in [SDS Configuration](#sds-configuration). Individual Envoy instances can also override the default behavior by configuring setting a `disable_spiffe_cert_validation` key in the Envoy node metadata.

## OpenShift Support

The default security profile of [OpenShift](https://www.openshift.com/products/container-platform) forbids access to host level resources. A custom set of policies can be applied to enable the level of access needed by Spire to operate within OpenShift.

_Note: A user with `cluster-admin` privileges is required in order to apply these policies._

### Security Context Constraints

Actions performed by pods are controlled by Security Context Constraints (SCC's) and every pod that is admitted is assigned a particular SCC depending on range of conditions. The following custom SCC with the name `spire` can be used to enable the necessary host level access needed by the Spire Agent

```yaml
allowHostDirVolumePlugin: true
allowHostIPC: true
allowHostNetwork: true
allowHostPID: true
allowHostPorts: true
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities: null
apiVersion: security.openshift.io/v1
defaultAddCapabilities: null
fsGroup:
  type: MustRunAs
groups: []
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/self-managed-high-availability: "true"
    kubernetes.io/description: Customized policy for Spire to enable host level access.
    release.openshift.io/create-only: "true"
  name: spire
priority: null
readOnlyRootFilesystem: false
requiredDropCapabilities:
  - KILL
  - MKNOD
  - SETUID
  - SETGID
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users: []
volumes:
  - hostPath
  - configMap
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - projected
  - secret
```

### Associating A Security Constraint With a Workload

Workloads can be granted access to Security Context Constraints through Role Based Access Control Policies by associating the SCC with the Service Account referenced by the pod.

In order to leverage the `spire` SCC, a _ClusterRole_ leveraging `use` verb referencing the SCC must be created:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    include.release.openshift.io/self-managed-high-availability: "true"
    rbac.authorization.kubernetes.io/autoupdate: "true"
  name: system:openshift:scc:spire
rules:
- apiGroups:
  - security.openshift.io
  resourceNames:
  - spire
  resources:
  - securitycontextconstraints
  verbs:
  - use
```

Finally, associate the `system:openshift:scc:spire` _ClusterRole_ to the `spire-agent` Service account by creating a _RoleBinding_ in the `spire` namespace

_Note:_ Create the `spire` namespace if it does exist prior to applying the following policy.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: system:openshift:scc:spire
  namespace: spire
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:spire
subjects:
  - kind: ServiceAccount
    name: spire-agent
    namespace: spire
```

As SCC's are applied at pod admission time, remove any existing Spire Agent pods. All newly admitted pods will make use of the `spire` SCC enabling their use within OpenShift.

## Further reading

- [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
- [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
