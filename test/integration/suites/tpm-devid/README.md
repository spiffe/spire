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

After the agent attests, the suite checks the selectors taken from the
provisioned DevID certificate (`subject:cn`, `issuer:cn`, `ca:fingerprint`)
and then points `devid_ca_path` at a CA that did not sign that certificate and
asserts attestation is rejected.

The unit tests continue to use the in-process simulator in `test/tpmsimulator`.
This suite covers the plugin against a separate TPM implementation.
