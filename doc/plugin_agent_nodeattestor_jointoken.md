# Agent plugin: NodeAttestor "join_token"

*Must be used in conjunction with the server-side join_token plugin*

The `join_token` is responsible for attesting the agent's identity using a one-time-use pre-shared key.

As a special case for node attestors, the join token itself is configured by a CLI flag (`-joinToken`)
or by configuring `join_token` in the agent's main config body.
