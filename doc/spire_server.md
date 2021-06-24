# SPIRE Server Configuration Reference

This document is a configuration reference for SPIRE Server. It includes information about plugin types, built-in plugins, the server configuration file, plugin configuration, and command line options for `spire-server` commands.

## Plugin types

| Type           | Description |
|:---------------|:------------|
| DataStore      | Provides persistent storage and HA features. **Note:** Pluggability for the DataStore is no longer supported. Only the built-in SQL plugin can be used. |
| KeyManager     | Implements both signing and key storage logic for the server's signing operations. Useful for leveraging hardware-based key operations. |
| NodeAttestor   | Implements validation logic for nodes attempting to assert their identity. Generally paired with an agent plugin of the same type. |
| NodeResolver   | A plugin capable of discovering platform-specific metadata of nodes which have been successfully attested. Discovered metadata is stored as selectors and can be used when creating registration entries. |
| UpstreamAuthority     | Allows SPIRE server to integrate with existing PKI systems. |
| Notifier       | Notified by SPIRE server for certain events that are happening or have happened. For events that are happening, the notifier can advise SPIRE server on the outcome. |

## Built-in plugins

| Type | Name | Description |
| ---- | ---- | ----------- |
| DataStore | [sql](/doc/plugin_server_datastore_sql.md) | An sql database storage for SQLite, PostgreSQL and MySQL databases for the SPIRE datastore |
| KeyManager  | [aws_kms](/doc/plugin_server_keymanager_aws_kms.md) | A key manager which manages keys in AWS KMS |
| KeyManager  | [disk](/doc/plugin_server_keymanager_disk.md) | A key manager which manages keys persisted on disk |
| KeyManager  | [memory](/doc/plugin_server_keymanager_memory.md) | A key manager which manages unpersisted keys in memory |
| NodeAttestor | [aws_iid](/doc/plugin_server_nodeattestor_aws_iid.md) | A node attestor which attests agent identity using an AWS Instance Identity Document |
| NodeAttestor | [azure_msi](/doc/plugin_server_nodeattestor_azure_msi.md) | A node attestor which attests agent identity using an Azure MSI token |
| NodeAttestor | [gcp_iit](/doc/plugin_server_nodeattestor_gcp_iit.md) | A node attestor which attests agent identity using a GCP Instance Identity Token |
| NodeAttestor | [join_token](/doc/plugin_server_nodeattestor_jointoken.md) | A node attestor which validates agents attesting with server-generated join tokens |
| NodeAttestor | [k8s_sat](/doc/plugin_server_nodeattestor_k8s_sat.md) | A node attestor which attests agent identity using a Kubernetes Service Account token |
| NodeAttestor | [k8s_psat](/doc/plugin_server_nodeattestor_k8s_psat.md) | A node attestor which attests agent identity using a Kubernetes Projected Service Account token |
| NodeAttestor | [sshpop](/doc/plugin_server_nodeattestor_sshpop.md) | A node attestor which attests agent identity using an existing ssh certificate |
| NodeAttestor | [x509pop](/doc/plugin_server_nodeattestor_x509pop.md) | A node attestor which attests agent identity using an existing X.509 certificate |
| NodeResolver | [azure_msi](/doc/plugin_server_noderesolver_azure_msi.md) | A node resolver which extends the [azure_msi](/doc/plugin_server_nodeattestor_azure_msi.md) node attestor plugin to support selecting nodes based on additional properties (such as Network Security Group). |
| Notifier   | [gcs_bundle](/doc/plugin_server_notifier_gcs_bundle.md) | A notifier that pushes the latest trust bundle contents into an object in Google Cloud Storage. |
| Notifier   | [k8sbundle](/doc/plugin_server_notifier_k8sbundle.md) | A notifier that pushes the latest trust bundle contents into a Kubernetes ConfigMap. |
| UpstreamAuthority | [disk](/doc/plugin_server_upstreamauthority_disk.md) | Uses a CA loaded from disk to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [aws_pca](/doc/plugin_server_upstreamauthority_aws_pca.md) | Uses a Private Certificate Authority from AWS Certificate Manager to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [awssecret](/doc/plugin_server_upstreamauthority_awssecret.md) | Uses a CA loaded from AWS SecretsManager to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [gcp_cas](/doc/plugin_server_upstreamauthority_gcp_cas.md) | Uses a Private Certificate Authority from GCP Certificate Authority Service to sign SPIRE Server intermediate certificates. |
| UpstreamAuthority | [vault](/doc/plugin_server_upstreamauthority_vault.md) | Uses a PKI Secret Engine from HashiCorp Vault to sign SPIRE server intermediate certificates. |
| UpstreamAuthority | [spire](/doc/plugin_server_upstreamauthority_spire.md) | Uses an upstream SPIRE server in the same trust domain to obtain intermediate signing certificates for SPIRE server. |
| UpstreamAuthority | [cert-manager](/doc/plugin_server_upstreamauthority_cert_manager.md) | Uses a referenced cert-manager Issuer to request intermediate signing certificates. |

## Server configuration file

The following table outlines the configuration options for SPIRE server. These may be set in a top-level `server { ... }` section of the configuration file. Most options have a corresponding CLI flag which, if set, takes precedence over values defined in the file.

SPIRE configuration files may be represented in either HCL or JSON. Please see the [sample configuration file](#sample-configuration-file) section for a complete example.

If the -expandEnv flag is passed to SPIRE, `$VARIABLE` or `${VARIABLE}` style environment variables are expanded before parsing.
This may be useful for templating configuration files, for example across different trust domains, or for inserting secrets like database connection passwords.

| Configuration               | Description                                                                                       | Default                                                        |
|:----------------------------|:--------------------------------------------------------------------------------------------------|:---------------------------------------------------------------|
| `bind_address`              | IP address or DNS name of the SPIRE server                                                        | 0.0.0.0                                                        |
| `bind_port`                 | HTTP Port number of the SPIRE server                                                              | 8081                                                           |
| `ca_key_type`               | The key type used for the server CA (both X509 and JWT), \<rsa-2048\|rsa-4096\|ec-p256\|ec-p384\> | ec-p256 (the JWT key type can be overridden by `jwt_key_type`) |
| `ca_subject`                | The Subject that CA certificates should use (see below)                                           |                                                                |
| `ca_ttl`                    | The default CA/signing key TTL                                                                    | 24h                                                            |
| `data_dir`                  | A directory the server can use for its runtime                                                    |                                                                |
| `default_svid_ttl`          | The default SVID TTL                                                                              | 1h                                                             |
| `experimental`              | The experimental options that are subject to change or removal (see below)                        |                                                                |
| `federation`                | Bundle endpoints configuration section used for [federation](#federation-configuration)           |                                                                |
| `jwt_key_type`              | The key type used for the server CA (JWT), \<rsa-2048\|rsa-4096\|ec-p256\|ec-p384\>               | The value of `ca_key_type` or ec-p256 if not defined           |
| `jwt_issuer`                | The issuer claim used when minting JWT-SVIDs                                                      |                                                                |
| `log_file`                  | File to write logs to                                                                             |                                                                |
| `log_level`                 | Sets the logging level \<DEBUG\|INFO\|WARN\|ERROR\>                                               | INFO                                                           |
| `log_format`                | Format of logs, \<text\|json\>                                                                    | text                                                           |
| `ratelimit`                 | Rate limiting configurations, usually used when the server is behind a load balancer (see below)  |                                                                |
| `socket_path`               | Path to bind the SPIRE Server API socket to                                                       | /tmp/spire-server/private/api.sock                             |
| `trust_domain`              | The trust domain that this server belongs to (should be no more than 255 characters)              |                                                                |

| ca_subject                  | Description                    | Default        |
|:----------------------------|--------------------------------|----------------|
| `country`                   | Array of `Country` values      |                |
| `organization`              | Array of `Organization` values |                |
| `common_name`               | The `CommonName` value         |                |

| experimental                | Description                    | Default        |
|:----------------------------|--------------------------------|----------------|
| `cache_reload_interval`     | The amount of time between two reloads of the in-memory entry cache. Increasing this will mitigate high database load for extra large deployments, but will also slow propagation of new or updated entries to agents. | 5s |

| ratelimit                   | Description                    | Default        |
|:----------------------------|--------------------------------|----------------|
| `attestation`               | Whether or not to rate limit node attestation. If true, node attestation is rate limited to one attempt per second per IP address. | true |
| `signing`                   | Whether or not to rate limit JWT and X509 signing. If true, JWT and X509 signing are rate limited to 500 requests per second per IP address (separately). | true |

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

## Federation configuration

SPIRE Server can be configured to federate with others SPIRE Servers living in different trust domains. This allows a trust domain to authenticate identities issued by other SPIFFE authorities, allowing workloads in one trust domain to securely autenticate workloads in a foreign trust domain.
A key element to achieve federation is the use of SPIFFE bundle endpoints, these are resources (represented by URLs) that serve a copy of a trust bundle for a trust domain.
Using the `federation` section you will be able to configure the bundle endpoints as follows:
```hcl
server {
    .
    .
    .
    federation {
        bundle_endpoint {
            address = "0.0.0.0"
            port = 8443
            acme {
                domain_name = "example.org"
                email = "mail@example.org"
            }
        }
        federates_with "domain1.test" {
            bundle_endpoint {
                address = "1.2.3.4"
                port = 8443
                use_web_pki = true
            }
        }
        federates_with "domain2.test" {
            bundle_endpoint {
                address = "5.6.7.8"
                port = 8443
                spiffe_id = "spiffe://domain2.test/beserver"
            }
        }
    }
}
```
Worth noting that the `federation.bundle_endpoint` and `federation.federates_with` sections are both optional.

### Configuration options for `federation.bundle_endpoint`
This optional section contains the configurables used by SPIRE Server to expose a bundle endpoint.

| Configuration   | Description                                                                    |
| --------------- | ------------------------------------------------------------------------------ |
| address         | IP address where this server will listen for HTTP requests                     |
| port            | TCP port number where this server will listen for HTTP requests                |
| acme            | Automated Certificate Management Environment configuration section (see below) |

### Configuration options for `federation.bundle_endpoint.acme`

| Configuration   | Description                                                                                                               | Default                                          |
| --------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| directory_url   | Directory endpoint URL                                                                                                    | "https://acme-v02.api.letsencrypt.org/directory" |
| domain_name     | Domain for which the certificate manager tries to retrieve new certificates                                               |                                                  |
| email           | Contact email address. This is used by CAs, such as Let's Encrypt, to notify about problems with issued certificates      |                                                  |
| tos_accepted    | ACME Terms of Service acceptance. If not true, and the provider requires acceptance, then certificate retrieval will fail | false                                            |

### Configuration options for `federation.federates_with["<trust domain>"].bundle_endpoint`

The optional `federates_with` section is a map of `bundle_endpoint` configurations keyed by the name of the `"<trust domain>"` this server wants to federate with. This `bundle_endpoint` configurations have the following configurables:

| Configuration   | Description                                                                                                                       | Default                                              |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------| ---------------------------------------------------- |
| address         | IP or DNS name of the bundle endpoint that provides the trust bundle to federate with `"<trust domain>"`                          |                                                      |
| port            | Port number of the bundle endpoint                                                                                                | 443                                                  |
| spiffe_id       | Expected SPIFFE ID of the bundle endpoint server. This is ignored if use_web_pki is true                                          | SPIRE Server SPIFFE ID within the `"<trust domain>"` |
| use_web_pki     | If true, indicates that this server must use Web PKI to authenticate the bundle endpoint, otherwise SPIFFE authentication is used | false                                                |

To clarify, `address` and `port` are used to form the bundle endpoint URL to federate with `"<trust domain>"` as follows:
```
https://<address>:<port>/
```

## Telemetry configuration

Please see the [Telemetry Configuration](./telemetry_config.md) guide for more information about configuring SPIRE Server to emit telemetry.

## Health check configuration

The server can expose an additional endpoint that can be used for health checking. It is enabled by setting `listener_enabled = true`. Currently it exposes 2 paths: one for liveness (is server up?) and one for readiness (is server ready to serve requests?). By default, health checking endpoint will listen on localhost:80, unless configured otherwise.

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

| Command          | Action                      | Default                 |
|:-----------------|:----------------------------|:------------------------|
| `-bindAddress` | IP address or DNS name of the SPIRE server | |
| `-config` | Path to a SPIRE config file | conf/server/server.conf |
| `-dataDir` | Directory to store runtime data to | |
| `-expandEnv` | Expand environment $VARIABLES in the config file | |
| `-logFile` | File to write logs to | |
| `-logFormat` | Format of logs, \<text\|json\> | |
| `-logLevel` | DEBUG, INFO, WARN or ERROR | |
| `-serverPort` | Port number of the SPIRE server | |
| `-socketPath` | Path to bind the SPIRE Server API socket to | |
| `-trustDomain` | The trust domain that this server belongs to (should be no more than 255 characters) | |

### `spire-server token generate`

Generates one node join token and creates a registration entry for it. This token can be used to
bootstrap one spire-agent installation. The optional `-spiffeID` can be used to give the token a
human-readable registration entry name in addition to the token-based ID.

| Command       | Action                                                    | Default        |
|:--------------|:----------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket                             | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | Additional SPIFFE ID to assign the token owner (optional) |                |
| `-ttl`        | Token TTL in seconds                                      | 600            |

### `spire-server entry create`

Creates registration entries.

| Command          | Action                                                                 | Default        |
|:-----------------|:-----------------------------------------------------------------------|:---------------|
| `-admin`         | If set, the SPIFFE ID in this entry will be granted access to the Server APIs | |
| `-data`          | Path to a file containing registration data in JSON format (optional). If set to '-', read the JSON from stdin. |                |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once | |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned from the datastore. Please note that this is a data management feature and not a security feature (optional).| |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist | |
| `-node`          | If set, this entry will be applied to matching nodes rather than workloads | |
| `-parentID`      | The SPIFFE ID of this record's parent.                                 |                |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied. | |
| `-socketPath`    | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued. | |
| `-ttl`           | A TTL, in seconds, for any SVID issued as a result of this record.     | The TTL configured with `default_svid_ttl` |

### `spire-server entry update`

Updates registration entries.

| Command          | Action                                                                 | Default        |
|:-----------------|:-----------------------------------------------------------------------|:---------------|
| `-admin`         | If true, the SPIFFE ID in this entry will be granted access to the Server APIs | |
| `-data`          | Path to a file containing registration data in JSON format (optional). If set to '-', read the JSON from stdin. |                |
| `-dns`           | A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once | |
| `-downstream`    | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryExpiry`   | An expiry, from epoch in seconds, for the resulting registration entry to be pruned | |
| `-entryID`       | The Registration Entry ID of the record to update                      |                |
| `-federatesWith` | A list of trust domain SPIFFE IDs representing the trust domains this registration entry federates with. A bundle for that trust domain must already exist | |
| `-parentID`      | The SPIFFE ID of this record's parent.                                 |                |
| `-selector`      | A colon-delimited type:value selector used for attestation. This parameter can be used more than once, to specify multiple selectors that must be satisfied. | |
| `-socketPath`    | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`      | The SPIFFE ID that this record represents and will be set to the SVID issued. | |
| `-ttl`           | A TTL, in seconds, for any SVID issued as a result of this record.     | The TTL configured with `default_svid_ttl` |

### `spire-server entry count`

Displays the total number of registration entries.

| Command       | Action                                             | Default        |
|:--------------|:---------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server entry delete`

Deletes a specified registration entry.

| Command       | Action                                             | Default        |
|:--------------|:---------------------------------------------------|:---------------|
| `-entryID`    | The Registration Entry ID of the record to delete  |                |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server entry show`

Displays configured registration entries.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-downstream` | A boolean value that, when set, indicates that the entry describes a downstream SPIRE server | |
| `-entryID`    | The Entry ID of the record to show.                                |                |
| `-federatesWith` | SPIFFE ID of a trust domain an entry is federate with. Can be used more than once | |
| `-parentID`   | The Parent ID of the records to show.                              |                |
| `-selector`   | A colon-delimeted type:value selector. Can be used more than once to specify multiple selectors. | |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the records to show.                              |                |

### `spire-server bundle count`

Displays the total number of bundles.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server bundle show`

Displays the bundle for the trust domain of the server.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-format` | The format to show the bundle. Either `pem` or `spiffe` | pem |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server bundle list`

Displays federated bundles.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to show. If unset, all trust bundles are shown | |
| `-format`     | The format to show the federated bundles. Either `pem` or `spiffe` | pem |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server bundle set`

Creates or updates bundle data for a trust domain. This command cannot be used to alter the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to set. | |
| `-path`       | Path on disk to the file containing the bundle data. If unset, data is read from stdin. | |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-format`     | The format of the bundle to set. Either `pem` or `spiffe` | pem |

### `spire-server bundle delete`

Deletes bundle data for a trust domain. This command cannot be used to delete the server trust domain bundle, only bundles for other trust domains.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-id`         | The trust domain SPIFFE ID of the bundle to delete. | |
| `-mode`       | One of: `restrict`, `dissociate`, `delete`. `restrict` prevents the bundle from being deleted if it is associated to registration entries (i.e. federated with). `dissociate` allows the bundle to be deleted and removes the association from registration entries. `delete` deletes the bundle as well as associated registration entries. | `restrict` |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server agent count`

Displays the total number of attested nodes.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server agent evict`

De-attesting an already attested node given its spiffeID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the agent to evict (agent identity) | |

### `spire-server agent list`

Displays attested nodes.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |

### `spire-server agent show`

Displays the details (including node selectors) of an attested node given its spiffeID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID` | The SPIFFE ID of the agent to show (agent identity) | |

### `spire-server healthcheck`

Checks SPIRE server's health.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-shallow`    | Perform a less stringent health check | |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-verbose`    | Print verbose information | |

### `spire-server validate`

Validates a SPIRE server configuration file.  Arguments are the same as `spire-server run`.
Typically, you may want at least:

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-config`     | Path to a SPIRE server configuration file                          | server.conf    |
| `-expandEnv`  | Expand environment $VARIABLES in the config file                   | false          |

### `spire-server x509 mint`

Mints an X509-SVID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-dns`        | A DNS name that will be included in SVID. Can be used more than once | |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the X509-SVID                                     | |
| `-ttl`        | The TTL of the X509-SVID                                           | The TTL configured with `default_svid_ttl` |
| `-write`      | Directory to write output to instead of stdout                     | |

### `spire-server jwt mint`

Mints a JWT-SVID.

| Command       | Action                                                             | Default        |
|:--------------|:-------------------------------------------------------------------|:---------------|
| `-audience`   | Audience claim that will be included in the SVID. Can be used more than once | |
| `-socketPath` | Path to the SPIRE Server API socket | /tmp/spire-server/private/api.sock |
| `-spiffeID`   | The SPIFFE ID of the JWT-SVID                                      | |
| `-ttl`        | The TTL of the JWT-SVID                                            | |
| `-write`      | File to write token to instead of stdout                           | |

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
    default_svid_ttl = "6h"
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

* [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
* [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
