# Agent plugin: KeyManager "memory"

The `memory` plugin generates an in-memory key pair for the agent's identity. If the agent is restarted,
the key pair is lost, and node attestation must be re-performed.

This plugin does not accept any configuration options.
