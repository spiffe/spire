# YAML Configuration

SPIRE Server and SPIRE Agent can read their configuration file in YAML as an alternative to HCL. YAML is selected by the file extension: a configuration file ending in `.yaml` or `.yml` is parsed as YAML, and any other file is parsed as HCL.

YAML configuration support is experimental and must be enabled by setting `enableYamlConfig` to `true` in the `experimental` section of the `server` or `agent` section. SPIRE refuses to start from a YAML configuration file without it, and logs a warning on startup when it is used. The configuration shape described in this document may change in future releases. Please see the [experimental features](upgrading.md#experimental-features) section of the upgrade guide for considerations about experimental features.

```yaml
server:
  experimental:
    enableYamlConfig: true
```

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

The rule only applies to option names. Plugin types (e.g. `KeyManager`), plugin names (e.g. `join_token`), the trust domain names under `federatesWith`, and all values are written exactly as in HCL.

Unknown keys are rejected. A misspelled option, or an option written with its HCL name, prevents SPIRE from starting. In the server and agent sections the unknown keys are logged, the same way as unknown HCL options; in plugin data, the plugin fails to configure:

```bash
$ spire-server run -config server.yaml
time="2026-11-14T15:57:20-03:00" level=error msg="Unknown configuration detected" keys="log_level (line 7)"
unknown configuration detected
```

Error messages that refer to configuration options, such as `trust_domain must be configured`, use the HCL option names.

Anchors, aliases and merge keys (`<<`) can be used. Aliases that refer to themselves, or that expand into an excessively large document, are rejected. A configuration file must contain a single YAML document.

Entries of a map or list that hold options, such as the clusters of `k8s_psat`, must not be null. An entry written without a value (e.g. `prod:`) is rejected; use an empty mapping (`{}`) for an entry without options.

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

For built-in plugins, plugin-specific data follows the same key naming rules as the rest of the file; external plugins define their own keys. A file referenced by `pluginDataFile` is parsed as YAML when its name ends in `.yaml` or `.yml`, and as HCL otherwise. This only applies to YAML configuration files: with an HCL configuration file, a file referenced by `plugin_data_file` is always parsed as HCL, whatever its extension.

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

In the configuration file, declare the plugin using the `pluginDataFile` option to source the plugin configuration from file.

```yaml
plugins:
  SomeType:
    some_plugin:
      pluginCmd: "./path/to/plugin"
      pluginChecksum: "5f2a1c86b0d5a1a6c2e2e1e0e5c9e0b14c1ad8e5a3c0fbb3b5d7f2f3c4a1e9d8"
      pluginDataFile: "some_plugin.yaml"
```

And then in `some_plugin.yaml` you place the plugin configuration:

```yaml
option1: "foo"
option2: 3
```

### External plugins

SPIRE sends the plugin configuration to external plugins together with its format. Plugins built with a version of the [SPIRE Plugin SDK](https://github.com/spiffe/spire-plugin-sdk) that predates YAML support only read the `hcl_configuration` field. When the plugin data is in YAML, SPIRE sets that field to a value that cannot be parsed as HCL, so those plugins fail to configure instead of running with a misread configuration.

**Note** An external plugin built with an older SDK fails to configure when its plugin data is in YAML, with an error that contains `YAML configuration requires a plugin built with a SPIRE plugin SDK that supports it`. Empty plugin data (`pluginData: {}`) is not affected. Before switching to YAML, make sure that every external plugin is built with an SDK version that supports YAML and handles YAML configuration, or keep its data in HCL by using `pluginDataFile` with a file that does not end in `.yaml` or `.yml`.

Plugin authors can support both formats by reading the `configuration` and `config_format` fields of the `Configure` and `Validate` requests.

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
  experimental:
    enableYamlConfig: true

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
  experimental:
    enableYamlConfig: true

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
