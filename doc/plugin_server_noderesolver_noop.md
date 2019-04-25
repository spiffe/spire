# Server plugin: NodeResolver "noop"

SPIRE server requires at least one NodeResolver plugin.
The `noop` is a dummy Node Resolver plugin for deployments which don't
require a NodeResolver.

A sample configuration:

```
    NodeResolver "noop" {
        plugin_data {}
    }
```
