# Agent plugin: nodeattestor-jointoken

*Must be used in conjunction with the server-side jointoken plugin*

The `nodeattestor-jointoken` is responsible for attesting the physical nodes identity using a
one-time-use pre-shared key.

The plugin accepts the following configuration options:

| Configuration | Description                                   |
| ------------- | --------------------------------------------- |
| trust_domain  | The trust domain of the join token            |
| join_token    | The join token to use to attest to the server |

The joinToken configuration option may also be passed to `spire-agent run` with the `-joinToken`
command-line flag.
