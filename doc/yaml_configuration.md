# YAML Configuration

SPIRE Server and SPIRE Agent can read their configuration file in YAML as an alternative to HCL. YAML is selected by the file extension: a configuration file ending in `.yaml` or `.yml` is parsed as YAML, and any other file is parsed as HCL.

YAML configuration support is experimental. SPIRE logs a warning on startup when a YAML configuration file is used, and the configuration shape described in this document may change in future releases. Please see the [experimental features](upgrading.md#experimental-features) section of the upgrade guide for considerations about experimental features.

Every option documented in the [SPIRE Server](spire_server.md) and [SPIRE Agent](spire_agent.md) configuration references, as well as every built-in plugin option, can be set in YAML. HCL configuration files are not affected and keep working as before.

## Key names

YAML keys are the HCL keys written in lowerCamelCase: each underscore is removed and the letter that follows it is capitalized. Keys without underscores are unchanged.

| HCL key                | YAML key             |
|------------------------|----------------------|
| `bind_address`         | `bindAddress`        |
| `trust_domain`         | `trustDomain`        |
| `ca_ttl`               | `caTtl`              |
| `x509_svid_ttl`        | `x509SvidTtl`        |
| `access_key_id`        | `accessKeyId`        |
| `endpoint_spiffe_id`   | `endpointSpiffeId`   |
| `health_checks`        | `healthChecks`       |
| `Prometheus`           | `Prometheus`         |

Acronyms follow the same rule, so `access_key_id` becomes `accessKeyId` and not `accessKeyID`.

Plugin types (e.g. `KeyManager`), plugin names (e.g. `join_token`), trust domain names and other values are not keys, and are written exactly as in HCL.

Unknown keys are rejected. A misspelled option, or an option written with its HCL name, prevents SPIRE from starting:

```bash
$ spire-server validate -config server.yaml
SPIRE server configuration file is invalid: unable to decode YAML configuration at "server.yaml": yaml: unmarshal errors:
  line 5: field trust_domain not found in type run.serverConfig
```

The `-expandEnv` flag is supported for YAML configuration files in the same way as for HCL.

## Plugin configuration

Plugin configurations live inside the top-level `plugins` section, which has the following format:

```yaml
plugins:
  pluginType:
    pluginName:
      ...
      plugin configuration options here
      ...
```

The following configuration options are available to configure a plugin:

| Configuration  | Description                                                                           |
|----------------|---------------------------------------------------------------------------------------|
| pluginCmd      | Path to the plugin implementation binary (optional, not needed for built-ins)         |
| pluginArgs     | Arguments passed to the plugin implementation binary (optional)                       |
| pluginChecksum | An optional sha256 of the plugin binary (optional, not needed for built-ins)          |
| enabled        | Enable or disable the plugin (enabled by default)                                     |
| pluginData     | Plugin-specific data (mutually exclusive with `pluginDataFile`)                       |
| pluginDataFile | Path to a file containing plugin-specific data (mutually exclusive with `pluginData`) |

For built-in plugins, plugin-specific data follows the same key naming rules as the rest of the file; external plugins define their own keys. When `pluginDataFile` is used, the file must also contain YAML, since its format is taken from the configuration file that references it.

### Examples

#### Built-in Plugin with Static Configuration

```yaml
plugins:
  SomeType:
    some_plugin:
      pluginData:
        option1: "foo"
        option2: 3
```

#### External Plugin with Dynamic Configuration

In the `agent.yaml`, declare the plugin using the `pluginDataFile` option to source the plugin configuration from file.

```yaml
plugins:
  SomeType:
    some_plugin:
      pluginCmd: "./path/to/plugin"
      pluginChecksum: "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83"
      pluginDataFile: "some_plugin.yaml"
```

And then in `some_plugin.yaml` you place the plugin configuration:

```yaml
option1: "foo"
option2: 3
```

### External plugins

SPIRE sends the plugin configuration to external plugins together with its format. Plugins built with a version of the [SPIRE Plugin SDK](https://github.com/spiffe/spire-plugin-sdk) that predates YAML support only read the HCL configuration field, which SPIRE leaves empty when the configuration is in YAML.

**Note** An external plugin built with an older SDK receives an empty configuration when SPIRE uses a YAML configuration file. SPIRE cannot detect this, so no error is reported by SPIRE itself; depending on the plugin, it either fails to configure or runs with its default settings. Before switching to YAML, make sure that every external plugin is built with an SDK version that supports YAML and that the plugin handles YAML configuration, or keep using HCL.

Plugin authors can support both formats by reading the `configuration` and `config_format` fields of the `Configure` and `Validate` requests. For HCL configuration files, SPIRE also keeps setting the `hcl_configuration` field, so plugins built with older SDKs continue to work.

## Options with a different shape

Some HCL options use blocks whose label selects a variant. In YAML these options are written as a mapping with a single key.

### DataStore `database_type`

`databaseType` is either a string or a mapping with a single key naming the database type. The supported keys are `awsMysql`, `awsPostgres`, `azureMysql` and `azurePostgres`.

```yaml
plugins:
  DataStore:
    sql:
      pluginData:
        databaseType:
          awsPostgres:
            region: "us-east-1"
        connectionString: "dbname=spire user=spire host=spire.example.org port=5432"
```

### Federation bundle endpoint profiles

The `profile` of `federation.bundleEndpoint` and the `bundleEndpointProfile` of each `federation.federatesWith` entry are mappings with a single key, `httpsSpiffe` or `httpsWeb`. A profile without options must be written as an empty mapping (`{}`), since a key without a value is not considered set.

```yaml
server:
  federation:
    bundleEndpoint:
      address: "0.0.0.0"
      port: 8443
      profile:
        httpsWeb:
          servingCertFile:
            certFilePath: "/path/to/cert.pem"
            keyFilePath: "/path/to/key.pem"
            fileSyncInterval: "1h"
    federatesWith:
      "domain1.test":
        bundleEndpointUrl: "https://1.2.3.4:8443"
        bundleEndpointProfile:
          httpsSpiffe:
            endpointSpiffeId: "spiffe://domain1.test/beserver"
      "domain2.test":
        bundleEndpointUrl: "https://example.org:8443"
        bundleEndpointProfile:
          httpsWeb: {}
```

## Sample configuration files

This section includes sample configuration files for formatting and syntax reference. They are the YAML equivalents of the `server.conf` and `agent.conf` files shipped in the `conf` directory.

### SPIRE Server

```yaml
server:
  bindAddress: "127.0.0.1"
  bindPort: 8081
  socketPath: "/tmp/spire-server/private/api.sock"
  trustDomain: "example.org"
  dataDir: "./.data"
  logLevel: "DEBUG"

plugins:
  DataStore:
    sql:
      pluginData:
        databaseType: "sqlite3"
        connectionString: "./.data/datastore.sqlite3"

  NodeAttestor:
    join_token:
      pluginData: {}

  KeyManager:
    memory:
      pluginData: {}

  UpstreamAuthority:
    disk:
      pluginData:
        keyFilePath: "./conf/server/dummy_upstream_ca.key"
        certFilePath: "./conf/server/dummy_upstream_ca.crt"

healthChecks:
  listenerEnabled: true
  bindAddress: "0.0.0.0"
  bindPort: "8080"
```

### SPIRE Agent

```yaml
agent:
  dataDir: "./.data"
  logLevel: "DEBUG"
  serverAddress: "127.0.0.1"
  serverPort: 8081
  socketPath: "/tmp/spire-agent/public/api.sock"
  trustBundlePath: "./conf/agent/dummy_root_ca.crt"
  trustDomain: "example.org"

plugins:
  NodeAttestor:
    join_token:
      pluginData: {}

  KeyManager:
    disk:
      pluginData:
        directory: "./.data"

  WorkloadAttestor:
    unix:
      pluginData: {}
```
