# SPIRE Server Configuration Reference

This document is a configuration reference for SPIRE Server. It includes information about plugin types, built-in plugins, the server configuration file, plugin configuration, and command line options for `spire-server` commands.

## Plugin types

| Type               | Description                                                                                                                                                          |
|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DataStore          | Provides persistent storage and HA features. **Note:** Pluggability for the DataStore is no longer supported. Only the built-in SQL plugin can be used.              |
| KeyManager         | Implements both signing and key storage logic for the server's signing operations. Useful for leveraging hardware-based key operations.                              |
| CredentialComposer | Allows customization of SVID and CA attributes.                                                                                                                      |
| NodeAttestor       | Implements validation logic for nodes attempting to assert their identity. Generally paired with an agent plugin of the same type.                                   |
| UpstreamAuthority  | Allows SPIRE server to integrate with existing PKI systems.                                                                                                          |
| Notifier           | Notified by SPIRE server for certain events that are happening or have happened. For events that are happening, the notifier can advise SPIRE server on the outcome. |
| BundlePublisher    | Publishes the local trust bundle to a store.                                                                                                                         |

## Built-in plugins

| Type               | Name                                                                                                 | Description                                                                                                                 |
|--------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| DataStore          | [sql](/doc/plugin_server_datastore_sql.md)                                                           | An SQL database storage for SQLite, PostgreSQL and MySQL databases for the SPIRE datastore                                  |
| KeyManager         | [aws_kms](/doc/plugin_server_keymanager_aws_kms.md)                                                  | A key manager which manages keys in AWS KMS                                                                                 |
| KeyManager         | [disk](/doc/plugin_server_keymanager_disk.md)                                                        | A key manager which manages keys persisted on disk                                                                          |
| KeyManager         | [memory](/doc/plugin_server_keymanager_memory.md)                                                    | A key manager which manages unpersisted keys in memory                                                                      |
| CredentialComposer | [uniqueid](/doc/plugin_server_credentialcomposer_uniqueid.md)                                        | Adds the x509UniqueIdentifier attribute to workload X509-SVIDs.                                                             |
| NodeAttestor       | [aws_iid](/doc/plugin_server_nodeattestor_aws_iid.md)                                                | A node attestor which attests agent identity using an AWS Instance Identity Document                                        |
| NodeAttestor       | [azure_msi](/doc/plugin_server_nodeattestor_azure_msi.md)                                            | A node attestor which attests agent identity using an Azure MSI token                                                       |
| NodeAttestor       | [gcp_iit](/doc/plugin_server_nodeattestor_gcp_iit.md)                                                | A node attestor which attests agent identity using a GCP Instance Identity Token                                            |
| NodeAttestor       | [join_token](/doc/plugin_server_nodeattestor_jointoken.md)                                           | A node attestor which validates agents attesting with server-generated join tokens                                          |
| NodeAttestor       | [k8s_psat](/doc/plugin_server_nodeattestor_k8s_psat.md)                                              | A node attestor which attests agent identity using a Kubernetes Projected Service Account token                             |
| NodeAttestor       | [sshpop](/doc/plugin_server_nodeattestor_sshpop.md)                                                  | A node attestor which attests agent identity using an existing ssh certificate                                              |
| NodeAttestor       | [tpm_devid](/doc/plugin_server_nodeattestor_tpm_devid.md)                                            | A node attestor which attests agent identity using a TPM that has been provisioned with a DevID certificate                 |
| NodeAttestor       | [x509pop](/doc/plugin_server_nodeattestor_x509pop.md)                                                | A node attestor which attests agent identity using an existing X.509 certificate                                            |
| UpstreamAuthority  | [disk](/doc/plugin_server_upstreamauthority_disk.md)                                                 | Uses a CA loaded from disk to sign SPIRE server intermediate certificates.                                                  |
| UpstreamAuthority  | [aws_pca](/doc/plugin_server_upstreamauthority_aws_pca.md)                                           | Uses a Private Certificate Authority from AWS Certificate Manager to sign SPIRE server intermediate certificates.           |
| UpstreamAuthority  | [awssecret](/doc/plugin_server_upstreamauthority_awssecret.md)                                       | Uses a CA loaded from AWS SecretsManager to sign SPIRE server intermediate certificates.                                    |
| UpstreamAuthority  | [gcp_cas](/doc/plugin_server_upstreamauthority_gcp_cas.md)                                           | Uses a Private Certificate Authority from GCP Certificate Authority Service to sign SPIRE Server intermediate certificates. |
| UpstreamAuthority  | [vault](/doc/plugin_server_upstreamauthority_vault.md)                                               | Uses a PKI Secret Engine from HashiCorp Vault to sign SPIRE server intermediate certificates.                               |
| UpstreamAuthority  | [spire](/doc/plugin_server_upstreamauthority_spire.md)                                               | Uses an upstream SPIRE server in the same trust domain to obtain intermediate signing certificates for SPIRE server.        |
| UpstreamAuthority  | [cert-manager](/doc/plugin_server_upstreamauthority_cert_manager.md)                                 | Uses a referenced cert-manager Issuer to request intermediate signing certificates.                                         |
| Notifier           | [gcs_bundle](/doc/plugin_server_notifier_gcs_bundle.md)                                              | A notifier that pushes the latest trust bundle contents into an object in Google Cloud Storage.                             |
| Notifier           | [k8sbundle](/doc/plugin_server_notifier_k8sbundle.md)                                                | A notifier that pushes the latest trust bundle contents into a Kubernetes ConfigMap.                                        |
| BundlePublisher    | [aws_s3](/doc/plugin_server_bundlepublisher_aws_s3.md)                                               | Publishes the trust bundle to an Amazon S3 bucket.                                                                          |
| BundlePublisher    | [gcp_cloudstorage](/doc/plugin_server_bundlepublisher_gcp_cloudstorage.md)                           | Publishes the trust bundle to a Google Cloud Storage bucket.                                                                |
| BundlePublisher    | [aws_rolesanywhere_trustanchor](/doc/plugin_server_bundlepublisher_aws_rolesanywhere_trustanchor.md) | Publishes the trust bundle to an AWS IAM Roles Anywhere trust anchor.                                                       |

## Server configuration file

The following table outlines the configuration options for SPIRE server. These may be set in a top-level `server { ... }` section of the configuration file. Most options have a corresponding CLI flag which, if set, takes precedence over values defined in the file.

SPIRE configuration files may be represented in either HCL or JSON. Please see the [sample configuration file](#sample-configuration-file) section for a complete example.

If the -expandEnv flag is passed to SPIRE, `$VARIABLE` or `${VARIABLE}` style environment variables are expanded before parsing.
This may be useful for templating configuration files, for example across different trust domains, or for inserting secrets like database connection passwords.

| Configuration                       | Description                                                                                                                                                                                                                                     | Default                                                        |
|:------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------|
| `admin_ids`                         | SPIFFE IDs that, when present in a caller's X509-SVID, grant that caller admin privileges. The admin IDs must reside on the server trust domain or a federated one, and need not have a corresponding admin registration entry with the server. |                                                                |
| `agent_ttl`                         | The TTL to use for agent SVIDs                                                                                                                                                                                                                  | The value of `default_x509_svid_ttl`                           |
| `audit_log_enabled`                 | If true, enables audit logging                                                                                                                                                                                                                  | false                                                          |
| `bind_address`                      | IP address or DNS name of the SPIRE server                                                                                                                                                                                                      | 0.0.0.0                                                        |
| `bind_port`                         | HTTP Port number of the SPIRE server                                                                                                                                                                                                            | 8081                                                           |
| `ca_key_type`                       | The key type used for the server CA (both X509 and JWT), &lt;rsa-2048&vert;rsa-4096&vert;ec-p256&vert;ec-p384&gt;                                                                                                                               | ec-p256 (the JWT key type can be overridden by `jwt_key_type`) |
| `ca_subject`                        | The Subject that CA certificates should use (see below)                                                                                                                                                                                         |                                                                |
| `ca_ttl`                            | The default CA/signing key TTL                                                                                                                                                                                                                  | 24h                                                            |
| `data_dir`                          | A directory the server can use for its runtime                                                                                                                                                                                                  |                                                                |
| `default_x509_svid_ttl`             | The default X509-SVID TTL                                                                                                                                                                                                                       | 1h                                                             |
| `default_jwt_svid_ttl`              | The default JWT-SVID TTL                                                                                                                                                                                                                        | 5m                                                             |
| `experimental`                      | The experimental options that are subject to change or removal (see below)                                                                                                                                                                      |                                                                |
| `federation`                        | Bundle endpoints configuration section used for [federation](#federation-configuration)                                                                                                                                                         |                                                                |
| `jwt_key_type`                      | The key type used for the server CA (JWT), &lt;rsa-2048&vert;rsa-4096&vert;ec-p256&vert;ec-p384&gt;                                                                                                                                             | The value of `ca_key_type` or ec-p256 if not defined           |
| `jwt_issuer`                        | The issuer claim used when minting JWT-SVIDs                                                                                                                                                                                                    |                                                                |
| `log_file`                          | File to write logs to                                                                                                                                                                                                                           |                                                                |
| `log_level`                         | Sets the logging level &lt;DEBUG&vert;INFO&vert;WARN&vert;ERROR&gt;                                                                                                                                                                             | INFO                                                           |
| `log_format`                        | Format of logs, &lt;text&vert;json&gt;                                                                                                                                                                                                          | text                                                           |
| `log_source_location`               | If true, logs include source file, line number, and method name fields (adds a bit of runtime cost)                                                                                                                                             | false                                                          |
| `profiling_enabled`                 | If true, enables a [net/http/pprof](https://pkg.go.dev/net/http/pprof) endpoint                                                                                                                                                                 | false                                                          |
| `profiling_freq`                    | Frequency of dumping profiling data to disk. Only enabled when `profiling_enabled` is `true` and `profiling_freq` > 0.                                                                                                                          |                                                                |
| `profiling_names`                   | List of profile names that will be dumped to disk on each profiling tick, see [Profiling Names](#profiling-names)                                                                                                                               |                                                                |
| `profiling_port`                    | Port number of the [net/http/pprof](https://pkg.go.dev/net/http/pprof) endpoint. Only used when `profiling_enabled` is `true`.                                                                                                                  |                                                                |
| `prune_attested_nodes_expired_for`  | Enables periodic purging of attested node records with expired SVIDs where the expiry time further in the past than the specidied duration. Non-reattestable nodes are not pruned unless `prune_tofu_nodes` is set to `true`. Banned nodes are not pruned. |
| `prune_tofu_nodes`                  | Includes expired TOFU nodes into consideration for pruning. This does not affect banned nodes, which are not pruned.                                                                                                                | false                                                          |
| `ratelimit`                         | Rate limiting configurations, usually used when the server is behind a load balancer (see below)                                                                                                                                                |                                                                |
| `socket_path`                       | Path to bind the SPIRE Server API socket to (Unix only)                                                                                                                                                                                         | /tmp/spire-server/private/api.sock                             |
| `trust_domain`                      | The trust domain that this server belongs to (should be no more than 255 characters)                                                                                                                                                            |                                                                |
| `max_attested_node_info_staleness`  | How long to cache and use attested node information before requiring fetching up to date data from the datastore.                                                                                                                               | 0s                                                             |

| ca_subject                  | Description                    | Default        |
|:----------------------------|--------------------------------|----------------|
| `country`                   | Array of `Country` values      |                |
| `organization`              | Array of `Organization` values |                |
| `common_name`               | The `CommonName` value         |                |

| experimental                 | Description                                                                                                                                                                                                            | Default                            |
|:-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `cache_reload_interval`      | The amount of time between two reloads of the in-memory entry cache. Increasing this will mitigate high database load for extra large deployments, but will also slow propagation of new or updated entries to agents. | 5s                                 |
| `full_cache_reload_interval` | How often to a full reload of the cache from the database when using the events based cache.                                                                                                                           | 24h                                |
| `events_based_cache`         | Use events to update the cache with what's changed since the last update. Enabling this will reduce overhead on the database.                                                                                          | false                              |
| `prune_events_older_than`    | How old an event can be before being deleted. Used with events based cache. Decreasing this will keep the events table smaller, but will increase risk of missing an event if connection to the database is down.      | 12h                                |
| `event_timeout`              | Maximum time to wait for an event to come in before giving up.                                                                                                                                                         | 15m                                |
| `auth_opa_policy_engine`     | The [auth opa_policy engine](/doc/authorization_policy_engine.md) used for authorization decisions                                                                                                                     | default SPIRE authorization policy |
| `named_pipe_name`            | Pipe name of the SPIRE Server API named pipe (Windows only)                                                                                                                                                            | \spire-server\private\api          |
| `require_pq_kem`             | Require use of a post-quantum-safe key exchange method for TLS handshakes                                                                                                                                              | false                              |

| ratelimit     | Description                                                                                                                                        | Default |
|:--------------|----------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `attestation` | whether to rate limit node attestation. If true, node attestation is rate limited to one attempt per second per IP address.                        | true    |
| `signing`     | whether to rate limit JWT and X509 signing. If true, JWT and X509 signing are rate limited to 500 requests per second per IP address (separately). | true    |

| auth_opa_policy_engine | Description                                       | Default |
|:-----------------------|---------------------------------------------------|---------|
| `local`                | Local OPA configuration for authorization policy. |         |

| auth_opa_policy_engine.local  | Description                                                                               | Default        |
|:------------------------------|-------------------------------------------------------------------------------------------|----------------|
| `rego_path`                   | File to retrieve OPA rego policy for authorization.                                       |                |
| `policy_data_path`            | File to retrieve databindings for policy evaluation.                                      |                |

### Profiling Names

These are the available profiles that can be set in the `profiling_names` configuration value:

- `goroutine`
- `threadcreate`
- `heap`
- `block`
- `mutex`
- `trace`
- `cpu`

## Plugin configuration

The server configuration file also contains a configuration section for the various SPIRE server plugins. Plugin configurations live inside the top-level `plugins { ... }` section, which has the following format:

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

Plugins that use dynamic configuration sources (i.e. `plugin_data_file`) can be reconfigured at runtime by sending a `SIGUSR1` signal to SPIRE Server. This is true for both built-in and external plugins.

SPIRE Server, upon receipt of the signal, does the following:

1. Reloads the plugin data
2. Compares the plugin data to the previous data
3. If changed, the plugin is reconfigured with the new data

**Note** The DataStore is not reconfigurable even when configured with a dynamic data source (e.g. `plugin_data_file`).

## Federation configuration

SPIRE Server can be configured to federate with others SPIRE Servers living in different trust domains. SPIRE supports configuring federation relationships in the SPIRE Server configuration file (static relationships) and through the [Trust Domain API](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/server/trustdomain/v1/trustdomain.proto) (dynamic relationships). This section describes how to configure statically defined relationships in the configuration file.

_Note: static relationships override dynamic relationships. If you need to configure dynamic relationships, see the [`federation`](#spire-server-federation-create) command. Static relationships are not reflected in the `federation` command._

Configuring a federated trust domain allows a trust domain to authenticate identities issued by other SPIFFE authorities, allowing workloads in one trust domain to securely authenticate workloads in a foreign trust domain.
A key element to achieve federation is the use of SPIFFE bundle endpoints, these are resources (represented by URLs) that serve a copy of a trust bundle for a trust domain.
Using the `federation` section you will be able to set up SPIRE as a SPIFFE bundle endpoint server and also configure the federated trust domains that this SPIRE Server will fetch bundles from.

```hcl
server {
    .
    .
    .
    federation {
        bundle_endpoint {
            address = "0.0.0.0"
            port = 8443
            refresh_hint = "10m"
            profile "https_web" {
                acme {
                    domain_name = "example.org"
                    email = "mail@example.org"
                }
            }
        }
        federates_with "domain1.test" {
            bundle_endpoint_url = "https://1.2.3.4:8443"
            bundle_endpoint_profile "https_web" {}
        }
        federates_with "domain2.test" {
            bundle_endpoint_url = "https://5.6.7.8:8443"
            bundle_endpoint_profile "https_spiffe" {
                endpoint_spiffe_id = "spiffe://domain2.test/beserver"
            }
        }
    }
}
```

The `federation.bundle_endpoint` section is optional and is used to set up a SPIFFE bundle endpoint server in SPIRE Server.
The `federation.federates_with` section is also optional and is used to configure the federation relationships with foreign trust domains. This section is used for each federated trust domain that SPIRE Server will periodically fetch the bundle.

### Configuration options for `federation.bundle_endpoint`

This optional section contains the configurables used by SPIRE Server to expose a bundle endpoint.

| Configuration                                 | Description                                                                                                                                                                                                                                        |
|-----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| address                                       | IP address where this server will listen for HTTP requests                                                                                                                                                                                         |
| port                                          | TCP port number where this server will listen for HTTP requests                                                                                                                                                                                    |
| refresh_hint                                  | Allow manually specifying a [refresh hint](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#412-refresh-hint). Defaults to 5 minutes. Small values allow to retrieve trust bundle updates in a timely manner |
| profile "&lt;https_web&vert;https_spiffe&gt;" | Allow to configure bundle profile                                                                                                                                                                                                                  |

### Configuration options for `federation.bundle_endpoint.profile`

When setting a `bundle_endpoint`, it is `required` to specify the bundle profile.

Allowed profiles:

- `https_web` allow to configure either the [Automated Certificate Management Environment](#configuration-options-for-federationbundle_endpointprofile-https_webacme) or the [serving cert file](#configuration-options-for-federationbundle_endpointprofile-https_webserving_cert_file) section.
- `https_spiffe`

### Configuration options for `federation.bundle_endpoint.profile "https_web".acme`

| Configuration | Description                                                                                                               | Default                                        |
|---------------|---------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| directory_url | Directory endpoint URL                                                                                                    | <https://acme-v02.api.letsencrypt.org/directory> |
| domain_name   | Domain for which the certificate manager tries to retrieve new certificates                                               |                                                |
| email         | Contact email address. This is used by CAs, such as Let's Encrypt, to notify about problems with issued certificates      |                                                |
| tos_accepted  | ACME Terms of Service acceptance. If not true, and the provider requires acceptance, then certificate retrieval will fail | false                                          |

### Configuration options for `federation.bundle_endpoint.profile "https_web".serving_cert_file`

| Configuration      | Description                                     | Default |
|--------------------|-------------------------------------------------|---------|
| cert_file_path     | Path to the certificate file, in PEM format     |         |
| key_file_path      | Path to the key file, in PEM format             |         |
| file_sync_interval | Interval on which to reload the files from disk | 1h      |

### Configuration options for `federation.bundle_endpoint.profile "https_spiffe"`

Default bundle profile configuration.

### Configuration options for `federation.federates_with["<trust domain>"].bundle_endpoint`

The optional `federates_with` section is a map of bundle endpoint profile configurations keyed by the name of the `"<trust domain>"` this server wants to federate with. This section has the following configurables:

| Configuration                                                 | Description                                                                                                     | Default |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|---------|
| bundle_endpoint_url                                           | URL of the SPIFFE bundle endpoint that provides the trust bundle to federate with. Must use the HTTPS protocol. |         |
| bundle_endpoint_profile "&lt;https_web&vert;https_spiffe&gt;" | Configuration of the SPIFFE endpoint profile type.                                                              |         |

SPIRE supports the `https_web` and `https_spiffe` bundle endpoint profiles.

The `https_web` profile does not require additional settings.

Trust domains configured with the `https_spiffe` bundle endpoint profile must specify the expected SPIFFE ID of the remote SPIFFE bundle endpoint server using the `endpoint_spiffe_id` setting as part of the configuration.

For more information about the different profiles defined in SPIFFE, along with the security considerations for setting up SPIFFE Federation, please refer to the [SPIFFE Federation standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md).

## Telemetry configuration

Please see the [Telemetry Configuration](./telemetry/telemetry_config.md) guide for more information about configuring SPIRE Server to emit telemetry.

## Health check configuration

The server can expose an additional endpoint that can be used for health checking. It is enabled by setting `listener_enabled = true`. Currently, it exposes 2 paths: one for liveness (is server up?) and one for readiness (is server ready to serve requests?). By default, health checking endpoint will listen on localhost:80, unless configured otherwise.

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

### `spire-server run`

Most of the configuration file above options have identical command-line counterparts. In addition, the following flags are available.

| Command        | Action                                                                               | Default                 |
|:---------------|:-------------------------------------------------------------------------------------|:------------------------|
| `-bindAddress` | IP address or DNS name of the SPIRE server                                           |                         |
| `-config`      | Path to a SPIRE config file                                                          | conf/server/server.conf |
| `-dataDir`     | Directory to store runtime data to                                                   |                         |
| `-expandEnv`   | Expand environment $VARIABLES in the config file                                     |                         |
| `-logFile`     | File to write logs to                                                                |                         |
| `-logFormat`   | Format of logs, &lt;text&vert;json&gt;                                               |                         |
| `-logLevel`    | DEBUG, INFO, WARN or ERROR                                                           |                         |
| `-serverPort`  | Port number of the SPIRE server                                                      |                         |
| `-socketPath`  | Path to bind the SPIRE Server API socket to                                          |                         |
| `-trustDomain` | The trust domain that this server belongs to (should be no more than 255 characters) |                         |

#### Running SPIRE Server as a Windows service

On Windows platform, SPIRE Server can optionally be run as a Windows service. When running as a Windows service, the only command supported is the `run` command.

_Note: SPIRE does not automatically create the service in the system, it must be created by the user.
When starting the service, all the arguments to execute SPIRE Server with the `run` command must be passed as service arguments._

##### Example to create the SPIRE Server Windows service

```bash
> sc.exe create spire-server binpath=c:\spire\bin\spire-server.exe
```

##### Example to run the SPIRE Server Windows service

```bash
> sc.exe start spire-server run -config c:\spire\conf\server\server.conf
```

### `spire-server token generate`

Generates one node join token and creates a registration entry for it. This token can be used to
bootstrap one spire-agent installation. The optional `-spiffeID` can be used to give the token a
human-readable registration entry name in addition to the token-based ID.

| Command       | Action                                                    | Default                            |
|:--------------|:----------------------------------------------------------|:-----------------------------------|
| `-socketPath` | Path to the SPIRE Server API socket                       | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | Additional SPIFFE ID to assign the token owner (optional) |                                    |
| `-ttl`        | Token TTL in seconds                                      | 600                                |

### `spire-server entry create`

Creates registration entries.

| Command          | Action                                                                                                                                                                                            | Default                                         |
|:-----------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------|
| `-admin`         | If set, the SPIFFE ID in this entry will be granted access to the Server APIs                                                                                                                     |                                                 |
| `-data`          | Path to a file containing registration data in JSON format (optional, if specified, other flags related with entry information must be omitted). If set to '-', read the JSON from stdin.         |                                                 |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once                                                                               |                                                 |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server                                                                                                      |                                                 |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned from the datastore. Please note that this is a data management feature and not a security feature (optional). |                                                 |
| `-entryID`       | A user-specified ID for the newly created registration entry (optional). If no entry ID is provided, one will be generated during creation                                                        |                                                 |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist                                        |                                                 |
| `-node`          | If set, this entry will be applied to matching nodes rather than workloads                                                                                                                        |                                                 |
| `-parentID`      | The SPIFFE ID of this record's parent.                                                                                                                                                            |                                                 |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied.                                      |                                                 |
| `-socketPath`    | Path to the SPIRE Server API socket                                                                                                                                                               | /tmp/spire-server/private/api.sock              |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued.                                                                                                                     |                                                 |
| `-x509SVIDTTL`   | A TTL, in seconds, for any X509-SVID issued as a result of this record.                                                                                                                           | The TTL configured with `default_x509_svid_ttl` |
| `-jwtSVIDTTL`    | A TTL, in seconds, for any JWT-SVID issued as a result of this record.                                                                                                                            | The TTL configured with `default_jwt_svid_ttl`  |
| `-storeSVID`     | A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin                                                               |

### `spire-server entry update`

Updates registration entries.

| Command          | Action                                                                                                                                                                                    | Default                                         |
|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------|
| `-admin`         | If true, the SPIFFE ID in this entry will be granted access to the Server APIs                                                                                                            |                                                 |
| `-data`          | Path to a file containing registration data in JSON format (optional, if specified, other flags related with entry information must be omitted). If set to '-', read the JSON from stdin. |                                                 |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once                                                                       |                                                 |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server                                                                                              |                                                 |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned                                                                                                       |                                                 |
| `-entryID`       | The Registration Entry ID of the record to update                                                                                                                                         |                                                 |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist                                |                                                 |
| `-parentID`      | The SPIFFE ID of this record's parent.                                                                                                                                                    |                                                 |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied.                              |                                                 |
| `-socketPath`    | Path to the SPIRE Server API socket                                                                                                                                                       | /tmp/spire-server/private/api.sock              |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued.                                                                                                             |                                                 |
| `-x509SVIDTTL`   | A TTL, in seconds, for any X509-SVID issued as a result of this record.                                                                                                                   | The TTL configured with `default_x509_svid_ttl` |
| `-jwtSVIDTTL`    | A TTL, in seconds, for any JWT-SVID issued as a result of this record.                                                                                                                    | The TTL configured with `default_jwt_svid_ttl`  |
| `storeSVID`      | A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin                                                       |

### `spire-server entry count`

Displays the total number of registration entries.

| Command          | Action                                                                                           | Default                            |
|:-----------------|:-------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server     |                                    |
| `-federatesWith` | SPIFFE ID of a trust domain an entry is federate with. Can be used more than once                |                                    |
| `-parentID`      | The Parent ID of the records to count.                                                            |                                    |
| `-selector`      | A colon-delimited type:value selector. Can be used more than once to specify multiple selectors. |                                    |
| `-socketPath`    | Path to the SPIRE Server API socket                                                              | /tmp/spire-server/private/api.sock |
| `-spiffeID`      | The SPIFFE ID of the records to count.                                                            |                                    |

### `spire-server entry delete`

Deletes a specified registration entry.

| Command       | Action                                            | Default                            |
|:--------------|:--------------------------------------------------|:-----------------------------------|
| `-entryID`    | The Registration Entry ID of the record to delete |                                    |
| `-socketPath` | Path to the SPIRE Server API socket               | /tmp/spire-server/private/api.sock |

### `spire-server entry show`

Displays configured registration entries.

| Command          | Action                                                                                           | Default                            |
|:-----------------|:-------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server     |                                    |
| `-entryID`       | The Entry ID of the record to show.                                                              |                                    |
| `-federatesWith` | SPIFFE ID of a trust domain an entry is federate with. Can be used more than once                |                                    |
| `-parentID`      | The Parent ID of the records to show.                                                            |                                    |
| `-selector`      | A colon-delimited type:value selector. Can be used more than once to specify multiple selectors. |                                    |
| `-socketPath`    | Path to the SPIRE Server API socket                                                              | /tmp/spire-server/private/api.sock |
| `-spiffeID`      | The SPIFFE ID of the records to show.                                                            |                                    |

### `spire-server bundle count`

Displays the total number of bundles.

| Command       | Action                              | Default                            |
|:--------------|:------------------------------------|:-----------------------------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server bundle show`

Displays the bundle for the trust domain of the server.

| Command       | Action                                                  | Default                            |
|:--------------|:--------------------------------------------------------|:-----------------------------------|
| `-format`     | The format to show the bundle. Either `pem` or `spiffe` | pem                                |
| `-socketPath` | Path to the SPIRE Server API socket                     | /tmp/spire-server/private/api.sock |

### `spire-server bundle list`

Displays federated bundles.

| Command       | Action                                                                                  | Default                            |
|:--------------|:----------------------------------------------------------------------------------------|:-----------------------------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to show. If unset, all trust bundles are shown |                                    |
| `-format`     | The format to show the federated bundles. Either `pem` or `spiffe`                      | pem                                |
| `-socketPath` | Path to the SPIRE Server API socket                                                     | /tmp/spire-server/private/api.sock |

### `spire-server bundle set`

Creates or updates bundle data for a trust domain. This command cannot be used to alter the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                                                  | Default                            |
|:--------------|:----------------------------------------------------------------------------------------|:-----------------------------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to set.                                        |                                    |
| `-path`       | Path on disk to the file containing the bundle data. If unset, data is read from stdin. |                                    |
| `-socketPath` | Path to the SPIRE Server API socket                                                     | /tmp/spire-server/private/api.sock |
| `-format`     | The format of the bundle to set. Either `pem` or `spiffe`                               | pem                                |

### `spire-server bundle delete`

Deletes bundle data for a trust domain. This command cannot be used to delete the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                                                                                                                                                                                                                                                                                                       | Default                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to delete.                                                                                                                                                                                                                                                                                          |                                    |
| `-mode`       | One of: `restrict`, `dissociate`, `delete`. `restrict` prevents the bundle from being deleted if it is associated to registration entries (i.e. federated with). `dissociate` allows the bundle to be deleted and removes the association from registration entries. `delete` deletes the bundle as well as associated registration entries. | `restrict`                         |
| `-socketPath` | Path to the SPIRE Server API socket                                                                                                                                                                                                                                                                                                          | /tmp/spire-server/private/api.sock |

### `spire-server federation create`

Creates a dynamic federation relationship with a foreign trust domain.

| Command                    | Action                                                                                                                                                                                                             | Default                            |
|:---------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-bundleEndpointProfile`   | Endpoint profile type. Either `https_web` or `https_spiffe`.                                                                                                                                                       |                                    |
| `-bundleEndpointURL`       | URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol).                                                                                                                    |                                    |
| `-data`                    | Path to a file containing federation relationships in JSON format (optional, if specified, other flags related with federation relationship information must be omitted). If set to '-', read the JSON from stdin. |                                    |
| `-endpointSpiffeID`        | SPIFFE ID of the SPIFFE bundle endpoint server. Only used for `https_spiffe` profile.                                                                                                                              |                                    |
| `-socketPath`              | Path to the SPIRE Server API socket.                                                                                                                                                                               | /tmp/spire-server/private/api.sock |
| `-trustDomain`             | Name of the trust domain to federate with (e.g., example.org)                                                                                                                                                      |                                    |
| `-trustDomainBundleFormat` | The format of the bundle data (optional). Either `pem` or `spiffe`.                                                                                                                                                | pem                                |
| `-trustDomainBundlePath`   | Path to the trust domain bundle data (optional).                                                                                                                                                                   |                                    |

### `spire-server federation delete`

Deletes a dynamic federation relationship.

| Command       | Action                                             | Default                            |
|:--------------|:---------------------------------------------------|:-----------------------------------|
| `-id`         | SPIFFE ID of the trust domain of the relationship. |                                    |
| `-socketPath` | Path to the SPIRE Server API socket.               | /tmp/spire-server/private/api.sock |

### `spire-server federation list`

Lists all the dynamic federation relationships.

| Command       | Action                                            | Default                            |
|:--------------|:--------------------------------------------------|:-----------------------------------|
| `-id`         | SPIFFE ID of the trust domain of the relationship |                                    |
| `-socketPath` | Path to the SPIRE Server API socket.              | /tmp/spire-server/private/api.sock |

### `spire-server federation refresh`

Refreshes the bundle from the specified federated trust domain.

| Command       | Action                                            | Default                            |
|:--------------|:--------------------------------------------------|:-----------------------------------|
| `-id`         | SPIFFE ID of the trust domain of the relationship |                                    |
| `-socketPath` | Path to the SPIRE Server API socket.              | /tmp/spire-server/private/api.sock |

### `spire-server federation show`

Shows a dynamic federation relationship.

| Command        | Action                                                                           | Default                            |
|:---------------|:---------------------------------------------------------------------------------|:-----------------------------------|
| `-socketPath`  | Path to the SPIRE Server API socket.                                             | /tmp/spire-server/private/api.sock |
| `-trustDomain` | The trust domain name of the federation relationship to show (e.g., example.org) |                                    |

### `spire-server federation update`

Updates a dynamic federation relationship with a foreign trust domain.

| Command                    | Action                                                                                                                                                                                                             | Default                            |
|:---------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-bundleEndpointProfile`   | Endpoint profile type. Either `https_web` or `https_spiffe`.                                                                                                                                                       |                                    |
| `-bundleEndpointURL`       | URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol).                                                                                                                    |                                    |
| `-data`                    | Path to a file containing federation relationships in JSON format (optional, if specified, other flags related with federation relationship information must be omitted). If set to '-', read the JSON from stdin. |                                    |
| `-endpointSpiffeID`        | SPIFFE ID of the SPIFFE bundle endpoint server. Only used for `https_spiffe` profile.                                                                                                                              |                                    |
| `-socketPath`              | Path to the SPIRE Server API socket.                                                                                                                                                                               | /tmp/spire-server/private/api.sock |
| `-trustDomain`             | Name of the trust domain to federate with (e.g., example.org)                                                                                                                                                      |                                    |
| `-trustDomainBundleFormat` | The format of the bundle data (optional). Either `pem` or `spiffe`.                                                                                                                                                | pem                                |
| `-trustDomainBundlePath`   | Path to the trust domain bundle data (optional).                                                                                                                                                                   |                                    |

### `spire-server agent ban`

Ban attested node given its spiffeID. A banned attested node is not able to re-attest.

| Command       | Action                                             | Default                            |
|:--------------|:---------------------------------------------------|:-----------------------------------|
| `-socketPath` | Path to the SPIRE Server API socket                | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the agent to ban (agent identity) |                                    |

### `spire-server agent count`

Displays the total number of attested nodes.

| Command       | Action                              | Default                            |
|:--------------|:------------------------------------|:-----------------------------------|
| `-selector`      | A colon-delimited type:value selector. Can be used more than once to specify multiple selectors. |                                    |
| `-canReattest`      | Filter based on string received, 'true': agents that can reattest, 'false': agents that can't reattest, other value will return all |                                    |
| `-banned`    |   Filter based on string received, 'true': banned agents, 'false': not banned agents, other value will return all |                |
| `-expiresBefore`      | Filter by expiration time (format: "2006-01-02 15:04:05 -0700 -07") |                                    |
| `-spiffeID`      | The SPIFFE ID of the records to count. |                                    |

### `spire-server agent evict`

De-attesting an already attested node given its spiffeID.

| Command       | Action                                               | Default                            |
|:--------------|:-----------------------------------------------------|:-----------------------------------|
| `-socketPath` | Path to the SPIRE Server API socket                  | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the agent to evict (agent identity) |                                    |

### `spire-server agent list`

Displays attested nodes.

| Command       | Action                              | Default                            |
|:--------------|:------------------------------------|:-----------------------------------|
| Command       | Action                              | Default                            |
|:--------------|:------------------------------------|:-----------------------------------|
| `-selector`      | A colon-delimited type:value selector. Can be used more than once to specify multiple selectors. |                                    |
| `-canReattest`      | Filter based on string received, 'true': agents that can reattest, 'false': agents that can't reattest, other value will return all |                                    |
| `-banned`    |   Filter based on string received, 'true': banned agents, 'false': not banned agents, other value will return all |                |
| `-expiresBefore`      | Filter by expiration time (format: "2006-01-02 15:04:05 -0700 -07")|                                    |
| `-attestationType`      |  Filters agents to those matching the attestation type, like join_token or x509pop. |         |

### `spire-server agent show`

Displays the details (including node selectors) of an attested node given its spiffeID.

| Command       | Action                                              | Default                            |
|:--------------|:----------------------------------------------------|:-----------------------------------|
| `-socketPath` | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the agent to show (agent identity) |                                    |

### `spire-server healthcheck`

Checks SPIRE server's health.

| Command       | Action                                | Default                            |
|:--------------|:--------------------------------------|:-----------------------------------|
| `-shallow`    | Perform a less stringent health check |                                    |
| `-socketPath` | Path to the SPIRE Server API socket   | /tmp/spire-server/private/api.sock |
| `-verbose`    | Print verbose information             |                                    |

### `spire-server validate`

Validates a SPIRE server configuration file.  Arguments are the same as `spire-server run`.
Typically, you may want at least:

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-config`     | Path to a SPIRE server configuration file                          | server.conf    |
| `-expandEnv`  | Expand environment $VARIABLES in the config file                   | false          |

### `spire-server x509 mint`

Mints an X509-SVID.

| Command       | Action                                                               | Default                                                                                                         |
|:--------------|:---------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------|
| `-dns`        | A DNS name that will be included in SVID. Can be used more than once |                                                                                                                 |
| `-socketPath` | Path to the SPIRE Server API socket                                  | /tmp/spire-server/private/api.sock                                                                              |
| `-spiffeID`   | The SPIFFE ID of the X509-SVID                                       |                                                                                                                 |
| `-ttl`        | The TTL of the X509-SVID                                             | First non-zero value from `Entry.x509_svid_ttl`, `Entry.ttl`, `default_x509_svid_ttl`, `1h` |
| `-write`      | Directory to write output to instead of stdout                       |                                                                                                                 |

### `spire-server jwt mint`

Mints a JWT-SVID.

| Command       | Action                                                                       | Default                                                                                   |
|:--------------|:-----------------------------------------------------------------------------|:------------------------------------------------------------------------------------------|
| `-audience`   | Audience claim that will be included in the SVID. Can be used more than once |                                                                                           |
| `-socketPath` | Path to the SPIRE Server API socket                                          | /tmp/spire-server/private/api.sock                                                        |
| `-spiffeID`   | The SPIFFE ID of the JWT-SVID                                                |                                                                                           |
| `-ttl`        | The TTL of the JWT-SVID                                                      | First non-zero value from `Entry.jwt_svid_ttl`, `Entry.ttl`, `default_jwt_svid_ttl`, `5m` |
| `-write`      | File to write token to instead of stdout                                     |                                                                                           |

### `spire-server localauthority jwt activate`

Activates a prepared JWT authority for use, which will cause it to be used for all JWT signing operations serviced by this server going forward.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the JWT authority to activate   |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority jwt prepare`

Prepares a new JWT authority for use by generating a new key and injecting it into the bundle.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority jwt revoke`

Revokes the previously active JWT authority by removing it from the bundle and propagating this update throughout the cluster.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the JWT authority to revoke     |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority jwt show`

Shows the local JWT authorities.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority jwt taint`

Marks the previously active JWT authority as being tainted.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the JWT authority to taint      |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority x509 activate`

Activates a prepared X.509 authority for use, which will cause it to be used for all X.509 signing operations serviced by this server going forward.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the X.509 authority to activate |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority x509 prepare`

Prepares a new X.509 authority for use by generating a new key and injecting the resulting CA certificate into the bundle.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority x509 revoke`

Revokes the previously active X.509 authority by removing it from the bundle and propagating this update throughout the cluster.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the X.509 authority to revoke   |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority x509 show`

Shows the local X.509 authorities.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server localauthority x509 taint`

Marks the previously active X.509 authority as being tainted.

| Command        | Action                                              | Default                            |
|:---------------|:----------------------------------------------------|:-----------------------------------|
| `-authorityID` | The authority ID of the X.509 authority to taint    |                                    |
| `-output`      | Desired output format (`pretty`, `json`)            | `pretty`                           |
| `-socketPath`  | Path to the SPIRE Server API socket                 | /tmp/spire-server/private/api.sock |

### `spire-server upstreamauthority revoke`

Revokes the previously active X.509 upstream authority by removing it from the bundle and propagating this update throughout the cluster.

| Command         | Action                                                                                                                 | Default                            |
|:----------------|:-----------------------------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-output`       | Desired output format (`pretty`, `json`)                                                                               | `pretty`                           |
| `-socketPath`   | Path to the SPIRE Server API socket                                                                                    | /tmp/spire-server/private/api.sock |
| `-subjectKeyID` | The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the X.509 upstream authority to revoke |                                    |

### `spire-server upstreamauthority taint`

Marks the provided X.509 upstream authority as being tainted.

| Command         | Action                                                                                                                 | Default                            |
|:----------------|:-----------------------------------------------------------------------------------------------------------------------|:-----------------------------------|
| `-output`       | Desired output format (`pretty`, `json`)                                                                               | `pretty`                           |
| `-socketPath`   | Path to the SPIRE Server API socket                                                                                    | /tmp/spire-server/private/api.sock |
| `-subjectKeyID` | The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the upstream X.509 authority to taint  |                                    |

## JSON object for `-data`

A JSON object passed to `-data` for `entry create/update` expects the following form:

```json
{
    "entries":[]
}
```

The entry object is described by `RegistrationEntry` in the [common protobuf file](https://github.com/spiffe/spire/blob/main/proto/spire/common/common.proto).

_Note: to create node entries, set `parent_id` to the special value `spiffe://<your-trust-domain>/spire/server`.
That's what the code does when the `-node` flag is passed on the cli._

## Sample configuration file

This section includes a sample configuration file for formatting and syntax reference

```hcl
server {
    trust_domain = "example.org"

    bind_address = "0.0.0.0"
    bind_port = "8081"
    log_level = "INFO"
    data_dir = "/opt/spire/.data/"
    default_x509_svid_ttl = "6h"
    default_jwt_svid_ttl = "5m"
    ca_ttl = "72h"
    ca_subject {
        country = ["US"]
        organization = ["SPIRE"]
        common_name = ""
    }
}

telemetry {
    Prometheus {
        port = 1234
    }
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/opt/spire/.data/datastore.sqlite3"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "disk" {
        plugin_data {
            keys_path = "/opt/spire/.data/keys.json"
        }
    }
}
```

## Further reading

- [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
- [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
