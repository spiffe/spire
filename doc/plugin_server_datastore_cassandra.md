# Server plugin: DataStore "cassandra"

The `cassandra` plugin is an experimental datastore plugin being prototyped to support allowing SPIRE servers to use [Apache Cassandra](https://cassandra.apache.org/) as a highly-available distributed database backend. This plugin is not officially supported and requires enabling an experimental flag in the `server` stanza of the SPIRE Server configuration file:
```hcl
server {
    ...
    experimental {
        allow_pluggable_datastore = true
    }
}
```

Adventurous users wanting to explore this plugin should be aware that it should be expected to be unstable and potentially lose data until it has been hardened. This plugin should not be run in production. This plugin has been developed and tested against Cassandra 5.0.6, and will not support versions of Cassandra prior to v5.0. 

When the Cassandra datastore is used, the 

## Cassandra configuration
