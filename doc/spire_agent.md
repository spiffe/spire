# SPIRE Agent Configuration Reference

This document is a configuration reference for SPIRE Agent. It includes information about plugin types, built-in plugins, the agent configuration file, plugin configuration, and command line options for `spire-agent` commands.

## Plugin types

| Type             | Description |
| ---------------- | ----------- |
| KeyManager       | Generates and stores the agent's private key. Useful for binding keys to hardware, etc. |
| NodeAttestor     | Gathers information used to attest the agent's identity to the server. Generally paired with a server plugin of the same type. |
| WorkloadAttestor | Introspects a workload to determine its properties, generating a set of selectors associated with it. |

## Built-in plugins

| Type             | Name | Description |
| ---------------- | ---- | ----------- |
| KeyManager       | [disk](/doc/plugin_agent_keymanager_disk.md) | A key manager which writes the private key to disk |
| KeyManager       | [memory](/doc/plugin_agent_keymanager_memory.md) | An in-memory key manager which does not persist private keys (must re-attest after restarts) |
| NodeAttestor     | [aws_iid](/doc/plugin_agent_nodeattestor_aws_iid.md) | A node attestor which attests agent identity using an AWS Instance Identity Document |
| NodeAttestor     | [azure_msi](/doc/plugin_agent_nodeattestor_azure_msi.md) | A node attestor which attests agent identity using an Azure MSI token |
| NodeAttestor     | [gcp_iit](/doc/plugin_agent_nodeattestor_gcp_iit.md) | A node attestor which attests agent identity using a GCP Instance Identity Token |
| NodeAttestor     | [join_token](/doc/plugin_agent_nodeattestor_jointoken.md) | A node attestor which uses a server-generated join token |
| NodeAttestor     | [k8s_sat](/doc/plugin_agent_nodeattestor_k8s_sat.md) | A node attestor which attests agent identity using a Kubernetes Service Account token |
| NodeAttestor     | [k8s_psat](/doc/plugin_agent_nodeattestor_k8s_psat.md) | A node attestor which attests agent identity using a Kubernetes Projected Service Account token |
| NodeAttestor     | [sshpop](/doc/plugin_agent_nodeattestor_sshpop.md) | A node attestor which attests agent identity using an existing ssh certificate |
| NodeAttestor     | [x509pop](/doc/plugin_agent_nodeattestor_x509pop.md) | A node attestor which attests agent identity using an existing X.509 certificate |
| WorkloadAttestor | [docker](/doc/plugin_agent_workloadattestor_docker.md) | A workload attestor which allows selectors based on docker constructs such `label` and `image_id`|
| WorkloadAttestor | [k8s](/doc/plugin_agent_workloadattestor_k8s.md) | A workload attestor which allows selectors based on Kubernetes constructs such `ns` (namespace) and `sa` (service account)|
| WorkloadAttestor | [unix](/doc/plugin_agent_workloadattestor_unix.md) | A workload attestor which generates unix-based selectors like `uid` and `gid` |

## Agent configuration file

The following table outlines the configuration options for SPIRE agent. These may be set in a top-level `agent { ... }` section of the configuration file. Most options have a corresponding CLI flag which, if set, takes precedence over values defined in the file.

SPIRE configuration files may be represented in either HCL or JSON. Please see the [sample configuration file](#sample-configuration-file) section for a complete example.

If the -expandEnv flag is passed to SPIRE, `$VARIABLE` or `${VARIABLE}` style environment variables are expanded before parsing.
This may be useful for templating configuration files, for example across different trust domains, or for inserting secrets like join tokens.

| Configuration             | Description                                                           | Default              |
| ------------------------- | --------------------------------------------------------------------- | -------------------- |
| `data_dir`                | A directory the agent can use for its runtime data                    | $PWD                 |
| `log_file`                | File to write logs to                                                 |                      |
| `log_level`               | Sets the logging level \<DEBUG\|INFO\|WARN\|ERROR\>                   | INFO                 |
| `log_format`              | Format of logs, \<text\|json\>                                        | Text                 |
| `server_address`          | DNS name or IP address of the SPIRE server                            |                      |
| `server_port`             | Port number of the SPIRE server                                       |                      |
| `socket_path`             | Location to bind the workload API socket                              | $PWD/spire_api       |
| `trust_bundle_path`       | Path to the SPIRE server CA bundle                                    |                      |
| `trust_bundle_url`        | URL to download the initial SPIRE server trust bundle                 |                      |
| `insecure_bootstrap`      | If true, the agent bootstraps without verifying the server's identity | false                |
| `trust_domain`            | The trust domain that this agent belongs to                           |                      |
| `join_token`              | An optional token which has been generated by the SPIRE server        |                      |
| `sds`                     | Optional SDS configuration section                                    |                      |

### Initial trust bundle configuration
The agent needs an initial trust bundle in order to connect securely to the SPIRE server. There are three options:
1. If the `trust_bundle_path` option is used, the agent will read the initial trust bundle from the file at that path. You need to copy or share the file before starting the SPIRE agent.
2. If the `trust_bundle_url` option is used, the agent will read the initial trust bundle from the specified URL. **The URL must start with `https://` for security, and the server must have a valid certificate (verified with the system trust store).** This can be used to rapidly deploy SPIRE agents without having to manually share a file. Keep in mind the contents of the URL need to be kept up to date.
3. If the `insecure_bootstrap` option is set to `true`, then the agent will not use an initial trust bundle. It will connect to the SPIRE server without authenticating it. This is not a secure configuration, because a man-in-the-middle attacker could control the SPIRE infrastructure. It is included because it is a useful option for testing and development.

Only one of these three options may be set at a time.


### SDS Configuration

| Configuration         | Description                                                                             | Default              |
| --------------------- | --------------------------------------------------------------------------------------- | -------------------- |
| `default_svid_name`   | The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS       | default              |
| `default_bundle_name` | The Validation Context resource name to use for the default X.509 bundle with Envoy SDS | ROOTCA               |


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

| Configuration   | Description                              |
| --------------- | ---------------------------------------- |
| plugin_cmd      | Path to the plugin implementation binary (optional, not needed for built-ins) |
| plugin_checksum | An optional sha256 of the plugin binary  (optional, not needed for built-ins) |
| enabled         | Enable or disable the plugin (enabled by default)            |
| plugin_data     | Plugin-specific data                     |

Please see the [built-in plugins](#built-in-plugins) section for information on plugins that are available out-of-the-box.

## Telemetry configuration

Please see the [Telemetry Configuration](./telemetry_config.md) guide for more information about configuring SPIRE Agent to emit telemetry.

## Health check configuration

The agent can expose additional endpoint that can be used for health checking. It is enabled by setting `listener_enabled = true`. Currently it exposes 2 paths: one for liveness (is agent up) and one for readiness (is agent ready to serve requests). By default, health checking endpoint will listen on localhost:80, unless configured otherwise.

```hcl
health_checks {
        listener_enabled = true
        bind_address = "localhost"
        bind_port = "80"
        live_path = "/live"
        ready_path = "/ready"
}
```

## Command line options

### `spire-agent run`

All of the configuration file above options have identical command-line counterparts. In addition,
the following flags are available:

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-config` | Path to a SPIRE config file | conf/agent/agent.conf |
| `-dataDir` | A directory the agent can use for its runtime data | |
| `-expandEnv` | Expand environment $VARIABLES in the config file | |
| `-joinToken` | An optional token which has been generated by the SPIRE server | |
| `-logFile` | File to write logs to | |
| `-logFormat` | Format of logs, \<text\|json\> | |
| `-logLevel` | DEBUG, INFO, WARN or ERROR | |
| `-serverAddress` | IP address or DNS name of the SPIRE server | |
| `-serverPort` | Port number of the SPIRE server | |
| `-socketPath` | Location to bind the workload API socket | |
| `-trustBundle` | Path to the SPIRE server CA bundle | |
| `-trustBundleUrl` | URL to download the SPIRE server CA bundle | |
| `-trustDomain` | The trust domain that this agent belongs to | |

### `spire-agent api fetch`

Calls the workload API to fetch an X509-SVID. This command is aliased to `spire-agent api fetch x509`.

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-silent` | Suppress stdout | |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |
| `-timeout` | Time to wait for a response | 1s |
| `-write` | Write SVID data to the specified path | |

### `spire-agent api fetch jwt`

Calls the workload API to fetch a JWT-SVID.

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-audience` | A comma separated list of audience values | |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |
| `-spiffeID` | The SPIFFE ID of the JWT being requested (optional) | |
| `-timeout` | Time to wait for a response | 1s |

### `spire-agent api fetch x509`

Calls the workload API to fetch a x.509-SVID.

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-silent` | Suppress stdout | |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |
| `-timeout` | Time to wait for a response | 1s |
| `-write` | Write SVID data to the specified path | |

### `spire-agent api validate jwt`

Calls the workload API to validate the supplied JWT-SVID.

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-audience` | A comma separated list of audience values | |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |
| `-svid` | The JWT-SVID to be validated | |
| `-timeout` | Time to wait for a response | 1s |

### `spire-agent api watch`

Attaches to the workload API and watches for X509-SVID updates, printing details when updates are received.

| Command          | Action                      | Default                 |
| ---------------- | --------------------------- | ----------------------- |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |

### `spire-agent healthcheck`

Checks SPIRE agent's health.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-shallow` | Perform a less stringent health check | |
| `-socketPath` | Path to the workload API socket | /tmp/agent.sock |
| `-verbose` | Print verbose information | |

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
    socket_path ="/tmp/agent.sock"
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

## Envoy SDS Support

SPIRE agent has support for the [Envoy](https://envoyproxy.io) [Secret Discovery Service](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret) (SDS).
SDS is served over the same Unix domain socket as the Workload API. Envoy processes connecting to SDS are attested as workloads.

[`auth.TlsCertificate`](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/auth/cert.proto#envoy-api-msg-auth-tlscertificate)
resources containing X.509-SVIDs can be fetched using the SPIFFE ID of the workload as the resource name (e.g. `spiffe://example.org/database`). Alternatively, if
requesting the default `auth.TlsCertificate`, the default name "default" may be used. The default name is configurable.

[`auth.CertificateValidationContext`](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/auth/cert.proto#auth-certificatevalidationcontext)
resources containing trusted CA certificates can be fetched using the SPIFFE ID of the desired trust domain as the resource name (e.g. `spiffe://example.org`). Alternatively, if
requesting the `auth.CertificateValidationContext` for the agent's trust domain, the default name "ROOTCA" may be used. The default name is configurable.

## Further reading

* [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
* [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
