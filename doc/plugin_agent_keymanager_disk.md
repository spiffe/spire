# Agent plugin: KeyManager "disk"

The `disk` plugin generates a key pair for the agent's identity, storing the private key
on disk. If the agent is restarted, the key will be loaded from disk. If the agent is unavailable
for long enough for its certificate to expire, attestation will need to be re-performed.

| Configuration | Description |
| ------------- | ----------- |
| directory     | The directory in which to store the private key. |
