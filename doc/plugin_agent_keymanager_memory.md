# Agent plugin: keymanager-memory

The `keymanager-memory` plugin is responsible for generating certificates for the Agent and
Workloads. Certificates contain ECDSA P-521 keys and are stored in memory only - any keys generated
are lost on restart.

This plugin does not accept any configuration options.
