# SPIRE Server

SPIRE Server is responsible for validating and signing all CSRs in the SPIFFE trust domain.
Validation is performed through platform-specific Attestation plugins, as well as policy enforcement
backed by the SPIRE Server datastore.

## Server configuration file

The following details the configurations for the spire server. The configurations can be set through
a .conf file or passed as command line args, the command line configurations takes precedence.

| Configuration     | Description                                            | Default                       |
|:------------------|:-------------------------------------------------------|:------------------------------|
| `base_svid_ttl`   | TTL to use when creating the base SPIFFE ID            |                               |
| `bind_address`    | IP address or DNS name of the SPIRE server             |                               |
| `bind_port`       | HTTP Port number of the SPIRE server                   |                               |
| `bind_http_port`  | The HTTP port where the SPIRE Service is set to listen |                               |
| `log_file`        | File to write logs to                                  |                               |
| `log_level`       | Sets the logging level \<DEBUG\|INFO\|WARN\|ERROR\>    | INFO                          |
| `trust_domain`    | The trust domain that this server belongs to           |                               |
| `umask`           | Umask value to use for new files                       | 0077                          |

**Note:** Changing the umask may expose your signing authority to users other than the SPIRE
agent/server

## Plugin configuration

The server configuration file also contains the configuration for the server plugins.
Plugins configurations are under the `plugins { ... }` section, which has the following format:

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
| plugin_cmd      | Path to the plugin implementation binary |
| plugin_checksum | An optional sha256 of the plugin binary  |
| enabled         | Enable or disable the plugin             |
| plugin_data     | Plugin-specific data                     |

## Command line options

### `spire-server run`

All of the configuration file above options have identical command-line counterparts. In addition, the following flags are available.

| Command          | Action                      | Default                 |
|:-----------------|:----------------------------|:------------------------|
| `-config string` | Path to a SPIRE config file | conf/server/server.conf |

### `spire-server token generate`

Generates one node join token and creates a registration entry for it. This token can be used to
bootstrap one spire-agent installation. The optional `-spiffeID` can be used to give the tooken a
human-readable registration entry name in addition to the token-based entry.

| Command       | Action                                                    | Default        |
|:--------------|:----------------------------------------------------------|:---------------|
| `-serverAddr` | Address of the SPIRE server to register with              | localhost:8081 |
| `-spiffeID`   | Additional SPIFFE ID to assign the token owner (optional) |                |
| `-ttl int`    | Token TTL in seconds                                      | 600            |

## Architechture

The server consists of a master process (spire-server) and five plugins - the CA, the Upstream CA,
The Data Store, the Node Attestor, and the Node Resolver. The master process implements the Registration
API and the Node API, with which agents communicate with the server.

![spire agent architecture](images/SPIRE_server.png)

## Available plugins

| Type           | Name                                                                   | Description |
|:---------------|:-----------------------------------------------------------------------|:------------|
| ControlPlaneCA | [ca-memory](/doc/plugin_server_ca_memory.md)                           |             |
| DataStore      | [datastore-sqlite](/doc/plugin_server_datastore_sqlite.md)             |             |
| NodeAttestor   | [nodeattestor-jointoken](/doc/plugin_server_nodeattestor_jointoken.md) |             |
| NodeResolver   | [noderesolver-noop](/doc/plugin_server_noderesolver_noop.md)           |             |
| UpstreamCA     | [upstreamca-memory](/doc/plugin_server_upstreamca_memory.md)           |             |

## Further reading

* [SPIFFE Reference Implementation Architecture](https://docs.google.com/document/d/1nV8ZbYEATycdFhgjTB619pwIvamzOjU6l0SyBGbzbo4/edit#)
* [Design Document: SPIFFE Reference Implementation (SRI)](https://docs.google.com/document/d/1RZnBfj8I5xs8Yi_BPEKBRp0K3UnIJYTDg_31rfTt4j8/edit#)
