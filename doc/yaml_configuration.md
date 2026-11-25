# YAML Configuration

SPIRE Server and SPIRE Agent can read their configuration file in YAML as an alternative to HCL. YAML is selected by the file extension: a configuration file ending in `.yaml` or `.yml` is parsed as YAML, and any other file is parsed as HCL.

YAML configuration support is experimental and must be enabled by setting `enable_yaml_config` to `true` in the `experimental` section of the `server` or `agent` section. SPIRE refuses to start from a YAML configuration file without it, and logs a warning on startup when it is used. The configuration shape described in this document may change in future releases. Please see the [experimental features](upgrading.md#experimental-features) section of the upgrade guide for considerations about experimental features.

```yaml
server:
  experimental:
    enable_yaml_config: true
```

Every option documented in the [SPIRE Server](spire_server.md) and [SPIRE Agent](spire_agent.md) configuration references, as well as every built-in plugin option, can be set in YAML. HCL configuration files are not affected and keep working as before.

## Key names

YAML keys are the same as the HCL keys, so every option keeps the name used in the [SPIRE Server](spire_server.md), [SPIRE Agent](spire_agent.md) and plugin documentation, and in error messages. Plugin types (e.g. `KeyManager`), plugin names (e.g. `join_token`), the trust domain names under `federates_with`, and all values are also written exactly as in HCL.

Unknown keys are rejected. A misspelled option prevents SPIRE from starting. In the server and agent sections the unknown keys are logged, the same way as unknown HCL options; in plugin data, the plugin fails to configure:

```bash
$ spire-server run -config server.yaml
time="2026-11-14T15:57:20-03:00" level=error msg="Unknown configuration detected" keys="log_levle (line 7)"
unknown configuration detected
```

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

| Configuration    | Description                                                                            |
|------------------|----------------------------------------------------------------------------------------|
| plugin_cmd       | Path to the plugin implementation binary (optional, not needed for built-ins)          |
| plugin_args      | Arguments passed to the plugin implementation binary (optional)                        |
| plugin_checksum  | An optional sha256 of the plugin binary (optional, not needed for built-ins)           |
| enabled          | Enable or disable the plugin (enabled by default)                                      |
| plugin_data      | Plugin-specific data (mutually exclusive with `plugin_data_file`)                      |
| plugin_data_file | Path to a file containing plugin-specific data (mutually exclusive with `plugin_data`) |

For built-in plugins, plugin-specific data uses the same keys as in HCL; external plugins define their own keys. A file referenced by `plugin_data_file` is parsed as YAML when its name ends in `.yaml` or `.yml`, and as HCL otherwise. This only applies to YAML configuration files: with an HCL configuration file, the file is always parsed as HCL, whatever its extension.

### Examples

#### Built-in Plugin with Static Configuration

```yaml
plugins:
  SomeType:
    some_plugin:
      plugin_data:
        option1: "foo"
        option2: 3
```

#### External Plugin with Dynamic Configuration

In the configuration file, declare the plugin using the `plugin_data_file` option to source the plugin configuration from file.

```yaml
plugins:
  SomeType:
    some_plugin:
      plugin_cmd: "./path/to/plugin"
      plugin_checksum: "5f2a1c86b0d5a1a6c2e2e1e0e5c9e0b14c1ad8e5a3c0fbb3b5d7f2f3c4a1e9d8"
      plugin_data_file: "some_plugin.yaml"
```

And then in `some_plugin.yaml` you place the plugin configuration:

```yaml
option1: "foo"
option2: 3
```

### External plugins

SPIRE sends the plugin configuration to external plugins together with its format. Plugins built with a version of the [SPIRE Plugin SDK](https://github.com/spiffe/spire-plugin-sdk) that predates YAML support only read the `hcl_configuration` field. When the plugin data is in YAML, SPIRE sets that field to a value that cannot be parsed as HCL, so those plugins fail to configure instead of running with a misread configuration.

**Note** An external plugin built with an older SDK fails to configure when its plugin data is in YAML, with an error that contains `YAML configuration requires a plugin built with a SPIRE plugin SDK that supports it`. Empty plugin data (`plugin_data: {}`) is not affected. Before switching to YAML, make sure that every external plugin is built with an SDK version that supports YAML and handles YAML configuration, or keep its data in HCL by using `plugin_data_file` with a file that does not end in `.yaml` or `.yml`.

Plugin authors can support both formats by reading the `configuration` and `config_format` fields of the `Configure` and `Validate` requests.

## Options with a different shape

Some HCL options use blocks whose label selects a variant. In YAML these options are written as a mapping with a single key.

### DataStore `database_type`

`database_type` is either a string or a mapping with a single key naming the database type. The supported keys are `aws_mysql`, `aws_postgres`, `azure_mysql` and `azure_postgres`.

```yaml
plugins:
  DataStore:
    sql:
      plugin_data:
        database_type:
          aws_postgres:
            region: "us-east-1"
        connection_string: "dbname=spire user=spire host=spire.example.org port=5432"
```

### Federation bundle endpoint profiles

The `profile` of `federation.bundle_endpoint` and the `bundle_endpoint_profile` of each `federation.federates_with` entry are mappings with a single key, `https_spiffe` or `https_web`. A profile without options must be written as an empty mapping (`{}`), since a key without a value is not considered set.

```yaml
server:
  federation:
    bundle_endpoint:
      address: "0.0.0.0"
      port: 8443
      profile:
        https_web:
          serving_cert_file:
            cert_file_path: "/path/to/cert.pem"
            key_file_path: "/path/to/key.pem"
            file_sync_interval: "1h"
    federates_with:
      "domain1.test":
        bundle_endpoint_url: "https://1.2.3.4:8443"
        bundle_endpoint_profile:
          https_spiffe:
            endpoint_spiffe_id: "spiffe://domain1.test/beserver"
      "domain2.test":
        bundle_endpoint_url: "https://example.org:8443"
        bundle_endpoint_profile:
          https_web: {}
```

## Sample configuration files

This section includes sample configuration files for formatting and syntax reference. They are the YAML equivalents of the `server.conf` and `agent.conf` files shipped in the `conf` directory.

### SPIRE Server

```yaml
server:
  bind_address: "127.0.0.1"
  bind_port: 8081
  socket_path: "/tmp/spire-server/private/api.sock"
  trust_domain: "example.org"
  data_dir: "./.data"
  log_level: "DEBUG"
  experimental:
    enable_yaml_config: true

plugins:
  DataStore:
    sql:
      plugin_data:
        database_type: "sqlite3"
        connection_string: "./.data/datastore.sqlite3"

  NodeAttestor:
    join_token:
      plugin_data: {}

  KeyManager:
    memory:
      plugin_data: {}

  UpstreamAuthority:
    disk:
      plugin_data:
        key_file_path: "./conf/server/dummy_upstream_ca.key"
        cert_file_path: "./conf/server/dummy_upstream_ca.crt"
```

### SPIRE Agent

```yaml
agent:
  data_dir: "./.data"
  log_level: "DEBUG"
  server_address: "127.0.0.1"
  server_port: 8081
  socket_path: "/tmp/spire-agent/public/api.sock"
  trust_bundle_path: "./conf/agent/dummy_root_ca.crt"
  trust_domain: "example.org"
  experimental:
    enable_yaml_config: true

plugins:
  NodeAttestor:
    join_token:
      plugin_data: {}

  KeyManager:
    disk:
      plugin_data:
        directory: "./.data"

  WorkloadAttestor:
    unix:
      plugin_data: {}
```
