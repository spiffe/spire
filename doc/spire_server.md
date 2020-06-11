# SPIRE Server Configuration Reference

This document is a configuration reference for SPIRE Server. It includes information about plugin types, built-in plugins, the server configuration file, plugin configuration, and command line options for `spire-server` commands.

## Plugin types

| Type           | Description |
|:---------------|:------------|
| DataStore      | Provides persistent storage and HA features. |
| KeyManager     | Implements both signing and key storage logic for the server's signing operations. Useful for leveraging hardware-based key operations. |
| NodeAttestor   | Implements validation logic for nodes attempting to assert their identity. Generally paired with an agent plugin of the same type. |
| NodeResolver   | A plugin capable of discovering platform-specific metadata of nodes which have been successfully attested. Discovered metadata is stored as selectors and can be used when creating registration entries. |
| UpstreamAuthority     | Allows SPIRE server to integrate with existing PKI systems. |
| Notifier       | Notified by SPIRE server for certain events that are happening or have happened. For events that are happening, the notifier can advise SPIRE server on the outcome. |

## Built-in plugins

| Type | Name | Description |
| ---- | ---- | ----------- |
| DataStore | [sql](/doc/plugin_server_datastore_sql.md) | An sql database storage for SQLite, PostgreSQL and MySQL databases for the SPIRE datastore |
| KeyManager  | [disk](/doc/plugin_server_keymanager_disk.md) | A disk-based key manager for signing SVIDs |
| KeyManager  | [memory](/doc/plugin_server_keymanager_memory.md) | A key manager for signing SVIDs which only stores keys in memory and does not actually persist them anywhere |
| NodeAttestor | [aws_iid](/doc/plugin_server_nodeattestor_aws_iid.md) | A node attestor which attests agent identity using an AWS Instance Identity Document |
| NodeAttestor | [azure_msi](/doc/plugin_server_nodeattestor_azure_msi.md) | A node attestor which attests agent identity using an Azure MSI token |
| NodeAttestor | [gcp_iit](/doc/plugin_server_nodeattestor_gcp_iit.md) | A node attestor which attests agent identity using a GCP Instance Identity Token |
| NodeAttestor | [join_token](/doc/plugin_server_nodeattestor_jointoken.md) | A node attestor which validates agents attesting with server-generated join tokens |
| NodeAttestor | [k8s_sat](/doc/plugin_server_nodeattestor_k8s_sat.md) | A node attestor which attests agent identity using a Kubernetes Service Account token |
| NodeAttestor | [k8s_psat](/doc/plugin_server_nodeattestor_k8s_psat.md) | A node attestor which attests agent identity using a Kubernetes Projected Service Account token |
| NodeAttestor | [sshpop](/doc/plugin_server_nodeattestor_sshpop.md) | A node attestor which attests agent identity using an existing ssh certificate |
| NodeAttestor | [x509pop](/doc/plugin_server_nodeattestor_x509pop.md) | A node attestor which attests agent identity using an existing X.509 certificate |
| NodeResolver | [aws_iid](/doc/plugin_server_noderesolver_aws_iid.md) | A node resolver which extends the [aws_iid](/doc/plugin_server_nodeattestor_aws_iid.md) node attestor plugin to support selecting nodes based on additional properties (such as Security Group ID). |
| NodeResolver | [azure_msi](/doc/plugin_server_noderesolver_azure_msi.md) | A node resolver which extends the [azure_msi](/doc/plugin_server_nodeattestor_azure_msi.md) node attestor plugin to support selecting nodes based on additional properties (such as Network Security Group). |
| NodeResolver | [noop](/doc/plugin_server_noderesolver_noop.md) | It is mandatory to have at least one node resolver plugin configured. This one is a no-op |
| Notifier   | [gcs_bundle](/doc/plugin_server_notifier_gcs_bundle.md) | A notifier that pushes the latest trust bundle contents into an object in Google Cloud Storage. |
| Notifier   | [k8sbundle](/doc/plugin_server_notifier_k8sbundle.md) | A notifier that pushes the latest trust bundle contents into a Kubernetes ConfigMap. |
| UpstreamAuthority | [disk](/doc/plugin_server_upstreamauthority_disk.md) | Uses a CA loaded from disk to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [aws_pca](/doc/plugin_server_upstreamauthority_aws_pca.md) | Uses a Private Certificate Authority from AWS Certificate Manager to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [awssecret](/doc/plugin_server_upstreamauthority_awssecret.md) | Uses a CA loaded from AWS SecretsManager to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [vault](/doc/plugin_server_upstreamauthority_vault.md) | Uses a PKI Secret Engine from HashiCorp Vault to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [spire](/doc/plugin_server_upstreamauthority_spire.md) | Uses an upstream SPIRE server in the same trust domain to obtain intermediate signing certificates for SPIRE server. |

## Server configuration file

The following table outlines the configuration options for SPIRE server. These may be set in a top-level `server { ... }` section of the configuration file. Most options have a corresponding CLI flag which, if set, takes precedence over values defined in the file.

SPIRE configuration files may be represented in either HCL or JSON. Please see the [sample configuration file](#sample-configuration-file) section for a complete example.

If the -expandEnv flag is passed to SPIRE, `$VARIABLE` or `${VARIABLE}` style environment variables are expanded before parsing.
This may be useful for templating configuration files, for example across different trust domains, or for inserting secrets like database connection passwords.

| Configuration               | Description                                                                   | Default                       |
|:----------------------------|:------------------------------------------------------------------------------|:------------------------------|
| `bind_address`              | IP address or DNS name of the SPIRE server                                    | 0.0.0.0                       |
| `bind_port`                 | HTTP Port number of the SPIRE server                                          | 8081                          |
| `ca_key_type`               | The key type used for the server CA, \<rsa-2048\|rsa-4096\|ec-p256\|ec-p384\> | ec-p256 (Both X509 and JWT)   |
| `ca_subject`                | The Subject that CA certificates should use (see below)                       |                               |
| `ca_ttl`                    | The default CA/signing key TTL                                                | 24h                           |
| `data_dir`                  | A directory the server can use for its runtime                                |                               |
| `jwt_issuer`                | The issuer claim used when minting JWT-SVIDs                                  |                               |
| `log_file`                  | File to write logs to                                                         |                               |
| `log_level`                 | Sets the logging level \<DEBUG\|INFO\|WARN\|ERROR\>                           | INFO                          |
| `log_format`                | Format of logs, \<text\|json\>                                                | text                          |
| `registration_uds_path`     | Location to bind the registration API socket                                  | /tmp/spire-registration.sock  |
| `default_svid_ttl`          | The default SVID TTL                                                          | 1h                            |
| `trust_domain`              | The trust domain that this server belongs to                                  |                               |
| `upstream_bundle`           | Include upstream CA certificates in the trust bundle                          | true                          |

| ca_subject Configuration    | Description                    | Default        |
|:----------------------------|--------------------------------|----------------|
| `country`                   | Array of `Country` values      |                |
| `organization`              | Array of `Organization` values |                |
| `common_name`               | The `CommonName` value         |                |

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

| Configuration   | Description                              |
| --------------- | ---------------------------------------- |
| plugin_cmd      | Path to the plugin implementation binary (optional, not needed for built-ins) |
| plugin_checksum | An optional sha256 of the plugin binary  (optional, not needed for built-ins) |
| enabled         | Enable or disable the plugin (enabled by default)             |
| plugin_data     | Plugin-specific data                     |

Please see the [built-in plugins](#built-in-plugins) section below for information on plugins that are available out-of-the-box.

## Telemetry configuration

Please see the [Telemetry Configuration](./telemetry_config.md) guide for more information about configuring SPIRE Server to emit telemetry.

## Health check configuration

The server can expose an additional endpoint that can be used for health checking. It is enabled by setting `listener_enabled = true`. Currently it exposes 2 paths: one for liveness (is server up?) and one for readiness (is server ready to serve requests?). By default, health checking endpoint will listen on localhost:80, unless configured otherwise.

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

### `spire-server run`

Most of the configuration file above options have identical command-line counterparts. In addition, the following flags are available.

| Command          | Action                      | Default                 |
|:-----------------|:----------------------------|:------------------------|
| `-bindAddress` | IP address or DNS name of the SPIRE server | |
| `-config` | Path to a SPIRE config file | conf/server/server.conf |
| `-dataDir` | Directory to store runtime data to | |
| `-expandEnv` | Expand environment $VARIABLES in the config file | |
| `-logFile` | File to write logs to | |
| `-logFormat` | Format of logs, \<text\|json\> | |
| `-logLevel` | DEBUG, INFO, WARN or ERROR | |
| `-registrationUDSPath` | UDS Path to bind registration API | |
| `-serverPort` | Port number of the SPIRE server | |
| `-trustDomain` | The trust domain that this server belongs to | |
| `-upstreamBundle` | Include upstream CA certificates in the bundle | |

### `spire-server token generate`

Generates one node join token and creates a registration entry for it. This token can be used to
bootstrap one spire-agent installation. The optional `-spiffeID` can be used to give the token a
human-readable registration entry name in addition to the token-based ID.

| Command       | Action                                                    | Default        |
|:--------------|:----------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-spiffeID`   | Additional SPIFFE ID to assign the token owner (optional) |                |
| `-ttl`        | Token TTL in seconds                                      | 600            |

### `spire-server entry create`

Creates registration entries.

| Command          | Action                                                                 | Default        |
|:-----------------|:-----------------------------------------------------------------------|:---------------|
| `-admin`         | If set, the SPIFFE ID in this entry will be granted access to the Registration API | |
| `-data`          | Path to a file containing registration data in JSON format (optional). |                |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once | |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned from the datastore. Please note that this is a data management feature and not a security feature (optional).| |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist | |
| `-node`          | If set, this entry will be applied to matching nodes rather than workloads | |
| `-parentID`      | The SPIFFE ID of this record's parent.                                 |                |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied. | |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued. | |
| `-ttl`           | A TTL, in seconds, for any SVID issued as a result of this record.     | 3600           |

### `spire-server entry update`

Updates registration entries.

| Command          | Action                                                                 | Default        |
|:-----------------|:-----------------------------------------------------------------------|:---------------|
| `-admin`         | If true, the SPIFFE ID in this entry will be granted access to the Registration API | |
| `-data`          | Path to a file containing registration data in JSON format (optional). |                |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once | |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned | |
| `-entryID`       | The Registration Entry ID of the record to update                      |                |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist | |
| `-parentID`      | The SPIFFE ID of this record's parent.                                 |                |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied. | |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued. | |
| `-ttl`           | A TTL, in seconds, for any SVID issued as a result of this record.     | 3600           |

### `spire-server entry delete`

Deletes a specified registration entry.

| Command       | Action                                             | Default        |
|:--------------|:---------------------------------------------------|:---------------|
| `-entryID`    | The Registration Entry ID of the record to delete  |                |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server entry show`

Displays configured registration entries.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-downstream` | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryID`    | The Entry ID of the record to show.                                |                |
| `-federatesWith` | SPIFFE ID of a trust domain an entry is federate with. Can be used more than once | |
| `-parentID`   | The Parent ID of the records to show.                              |                |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-selector`   | A colon-delimeted type:value selector. Can be used more than once to specify multiple selectors. | |
| `-spiffeID`   | The SPIFFE ID of the records to show.                              |                |

### `spire-server bundle show`

Displays the bundle for the trust domain of the server.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server bundle list`

Displays bundles from other trust domains.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to show. If unset, all trust bundles are shown | |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server bundle set`

Creates or updates bundle data for a trust domain. This command cannot be used to alter the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to set. | |
| `-path`       | Path on disk to the file containing the bundle data. If unset, data is read from stdin. | |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server bundle delete`

Deletes bundle data for a trust domain. This command cannot be used to delete the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to delete. | |
| `-mode`       | One of: `restrict`, `dissociate`, `delete`. `restrict` prevents the bundle from being deleted if it is associated to registration entries (i.e. federated with). `dissociate` allows the bundle to be deleted and removes the association from registration entries. `delete` deletes the bundle as well as associated registration entries. | `restrict` |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server agent evict`

De-attesting an already attested node given its spiffeID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-spiffeID` | The SPIFFE ID of the agent to evict (agent identity) | |

### `spire-server agent list`

Displays attested nodes.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server agent show`

Displays the details (including node selectors) of an attested node given its spiffeID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-spiffeID` | The SPIFFE ID of the agent to show (agent identity) | |

### `spire-server healthcheck`

Checks SPIRE server's health.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |
| `-shallow` | Perform a less stringent health check | |
| `-verbose` | Print verbose information | |

### `spire-server validate`

Validates a SPIRE server configuration file.  Arguments are the same as `spire-server run`.
Typically, you may want at least:

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-config`     | Path to a SPIRE server configuration file                          | server.conf    |
| `-expandEnv`  | Expand environment $VARIABLES in the config file                   | false          |

### `spire-server experimental bundle show`

(Experimental) Displays the bundle for the trust domain of the server as a JWKS document

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server experimental bundle list`

(Experimental) Displays bundles from other trust domains as JWKS documents

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to show. If unset, all trust bundles are shown | |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

### `spire-server experimental bundle set`

(Experimental) Creates or updates bundle data for a trust domain. This command cannot be used to alter the server trust domain bundle, only bundles for other trust domains.

Bundle data read from stdin or the path is expected to be a JWKS document.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-path`       | Path on disk to the file containing the bundle data. If unset, data is read from stdin. | |
| `-registrationUDSPath` | Path to the SPIRE server registration api socket | /tmp/spire-registration.sock |

## Sample configuration file

This section includes a sample configuration file for formatting and syntax reference

```hcl
server {
    trust_domain = "example.org"

    bind_address = "0.0.0.0"
    bind_port = "8081"
    log_level = "INFO"
    data_dir = "/opt/spire/.data/"
    registration_uds_path = "/opt/spire/registration.sock"
    default_svid_ttl = "6h"
    ca_ttl = "72h"
    ca_subject = {
        country = ["US"],
        organization = ["SPIRE"],
        common_name = "",
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
    NodeResolver "noop" {
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

* [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
* [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
