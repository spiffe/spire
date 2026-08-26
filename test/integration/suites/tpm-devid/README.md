# TPM DevID Suite

## Description

Exercises the `tpm_devid` node attestor end to end against a software TPM
(swtpm) running in its own container.

The agent reaches the TPM over a unix socket on a shared volume, which go-tpm
dials using its emulator transport, so no TPM device or extra container
privileges are required.

`test/integration/setup/tpmdevid` provisions the TPM before the agent starts:
it creates the endorsement key and stores its certificate in the NV index the
agent reads, creates the DevID key under the storage root key the agent loads
it with, and writes the DevID credentials for the agent and the CA bundles for
the server.

The unit tests continue to use the in-process simulator in `test/tpmsimulator`.
This suite covers the plugin against a separate TPM implementation.
