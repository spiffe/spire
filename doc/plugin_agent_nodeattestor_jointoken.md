# Agent plugin: nodeattestor-jointoken

The `nodeattestor-jointoken` is responsible for attesting the physical nodes identity using a
one-time-use pre-shared key.

The plugin accepts the following configuration options:

| Configuration | Description                                   |
| ------------- | --------------------------------------------- |
| trustDomain  | The trust domain of the join token            |
| joinToken    | The join token to use to attest to the server |

The joinToken configuration option may also be passed to `spire-agent run` with the `-joinToken`
command-line flag.
