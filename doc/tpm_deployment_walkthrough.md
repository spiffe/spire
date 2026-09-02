# TPM Deployment Walkthrough

This guide describes a redundant SPIRE deployment using TPM 2.0 for node
attestation in non-Kubernetes environments.

## Architecture

A production-ready setup consists of a high-availability SPIRE Server cluster
and agents running on hardware with TPM 2.0 support.

- **Control Plane**: Multiple servers sharing a SQL datastore (Postgres or
  MySQL) for persistence and HA.
- **Agent Nodes**: Physical or virtual infrastructure with a TPM 2.0 device
  accessible via the kernel driver.
- **LDevID**: TPM-bound Local Device Identifiers provisioned out-of-band.

## Requirements

- **TPM 2.0 hardware**: A TPM 2.0 device accessible via the kernel driver. The
  agent plugin autodetects the path, preferring the resource manager device
  (`/dev/tpmrm0`) over the raw device (`/dev/tpm0`); set `tpm_device_path`
  explicitly if autodetection fails. Prefer the resource manager device: the raw
  device allows a single client at a time, so the agent competes with any other
  TPM consumer on the host. Whichever is used, the account running the agent
  needs read/write access to it, typically by way of the `tss` group.
- **An endorsement certificate in the TPM**: Proof-of-residency requires the
  server to chain the TPM's endorsement key to a manufacturer CA. Discrete TPMs
  are generally shipped with an EK certificate in NV storage, but some firmware
  TPMs (fTPM/PTT) are not, in which case the `tpm_devid` attestor cannot be
  used. Verify before rolling out:

  ```shell
  tpm2_nvread 0x1c00002 | openssl x509 -inform DER -noout -subject -issuer
  ```

- **Provisioning tooling**: [`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools)
  and [`tpm2-openssl`](https://github.com/tpm2-software/tpm2-openssl), which
  provides the OpenSSL `tpm2` provider used to generate the CSR:

  ```shell
  # Debian/Ubuntu
  apt-get install -y tpm2-tools tpm2-openssl

  # Fedora/RHEL
  dnf install -y tpm2-tools tpm2-openssl
  ```

- **Pre-provisioned LDevID**: Key blobs and certificates must be on-node before
  starting the agent.
- **Internal CA**: The CA that signed the LDevIDs must be trusted by the
  SPIRE Server.
- **TPM manufacturer CA certificates**: The CAs that signed the TPMs'
  endorsement certificates must be trusted by the SPIRE Server. These are
  published by the TPM vendor rather than by SPIRE, and are specific to the
  manufacturer and part in use, so collect the roots and intermediates for every
  TPM model in the fleet before deploying. See
  [Collecting manufacturer CA certificates](#collecting-manufacturer-ca-certificates).

> [!TIP]
> Use `tpm2-tools` to verify TPM access and key residency before configuring
> the SPIRE plugin.

## Setup Walkthrough

### 1. Provisioning

Before configuring SPIRE, each node's TPM must be provisioned with a Local
Device Identifier (LDevID) out-of-band. The following steps use
[`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools) and the
[`tpm2-openssl`](https://github.com/tpm2-software/tpm2-openssl) provider for
OpenSSL.

**a. Create a primary storage key using the TCG H-2 SRK template:**

```shell
tpm2_createprimary -C o -g sha256 -G ecc256:aes128cfb \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
  -c /tmp/primary.ctx
```

> [!IMPORTANT]
> The primary key attributes must match the H-2 SRK template that SPIRE uses
> internally to reload the key blobs. Using different attributes will produce
> a different parent key and cause the agent to fail loading the DevID.

The commands in this section assume the owner hierarchy has an empty
authorization value. That is true of a cleared TPM, but not of one already
owned by a previous operating system install or by a platform provisioning
step, where these commands fail with a `bad auth` (`0x9a2`) error. Pass the
owner authorization with `-P` on each command that uses `-C o`:

```shell
tpm2_createprimary -C o -P "$TPM_OWNER_AUTH" -g sha256 -G ecc256:aes128cfb \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
  -c /tmp/primary.ctx
```

> [!IMPORTANT]
> The agent recreates this primary key on every attestation, so it authorizes
> against the owner hierarchy exactly as provisioning did. Whatever value is
> used here must also be set as `owner_hierarchy_password` in the agent
> configuration, otherwise the agent cannot reload the DevID.

Clearing the TPM (`tpm2_clear -c p`) resets the owner authorization, but it also
invalidates every existing key and any other credential bound to the TPM. Only
do this on hardware known not to be in use by anything else.

**b. Create the LDevID signing key (fixed to the TPM — the private key never
leaves the hardware):**

```shell
tpm2_create \
  -C /tmp/primary.ctx \
  -G ecc:ecdsa-sha256 \
  -u /tmp/devid.pub.blob \
  -r /tmp/devid.priv.blob \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"
```

**c. Convert the key blobs to the format the SPIRE Agent expects:**

`tpm2_create` writes each blob in its TPM2B form, prefixed with a two-byte
big-endian length. The agent reads `devid_pub_path` and `devid_priv_path` as
raw `TPMT_PUBLIC` and `TPMT_PRIVATE` structures, so the prefix must be stripped
from both files:

```shell
tail -c +3 /tmp/devid.pub.blob  > /opt/spire/conf/agent/devid.pub.blob
tail -c +3 /tmp/devid.priv.blob > /opt/spire/conf/agent/devid.priv.blob
```

> [!IMPORTANT]
> Skipping this conversion causes the agent to fail at startup while loading
> the DevID, with `decoding TPMT_PUBLIC: unexpected EOF` if the public blob
> still carries its prefix, or `structure is the wrong size` if only the
> private blob does.

**d. Load the key, make it temporarily persistent, and generate a Certificate
Signing Request (CSR):**

The unconverted blobs in `/tmp` are the ones `tpm2_load` expects here. The key
is made persistent only because the OpenSSL `tpm2` provider addresses keys by
persistent handle; it is evicted again as soon as the CSR exists.

Persistent handles are a shared resource, and the conventional first handle
(`0x81000001`) is often already occupied on hardware that has been provisioned
before. Pick one that is free rather than assuming, and evict it even if the
CSR fails, so a retry does not collide with the previous attempt:

```shell
# Choose the first free handle in the persistent range
for h in $(seq 0x81000001 0x8100000f); do
  handle=$(printf "0x%x" "$h")
  tpm2_getcap handles-persistent | grep -q "$handle" || break
done

tpm2_load \
  -C /tmp/primary.ctx \
  -u /tmp/devid.pub.blob \
  -r /tmp/devid.priv.blob \
  -c /tmp/devid.ctx

tpm2_evictcontrol -C o -c /tmp/devid.ctx "$handle"
trap 'tpm2_evictcontrol -C o -c "$handle" 2>/dev/null' EXIT

openssl req \
  -provider tpm2 \
  -provider default \
  -new \
  -key "handle:$handle" \
  -out /tmp/devid.csr \
  -subj "/CN=$(hostname -f)/O=Example Org"
```

> [!NOTE]
> Add `-P "$TPM_OWNER_AUTH"` to both `tpm2_evictcontrol` invocations if the
> owner hierarchy is protected, as described in step (a).

**e. Submit the CSR to your internal CA and store the signed certificate:**

The CA-specific signing step is out of scope here, but the returned certificate
should be placed at `/opt/spire/conf/agent/devid.crt.pem`. The three resulting
artifacts — `devid.crt.pem`, `devid.pub.blob`, and `devid.priv.blob` — are
what the SPIRE Agent configuration requires.

> [!NOTE]
> `/tmp/primary.ctx` and `/tmp/devid.ctx` are volatile TPM context handles used
> only during provisioning. They do not need to be retained after the CSR is
> signed. The agent reloads the DevID from the key blobs under a primary key it
> recreates itself, so no persistent handle is left occupied on the node.

These artifacts establish the initial hardware-bound identity that the SPIRE
Agent will use to attest to the Server.

### 2. SPIRE Server Configuration

Configure the `tpm_devid` attestor in the SPIRE Server configuration file
(`server.conf`). Two trust bundles are required, and the server fails to
configure if either is missing:

- `devid_ca_path`: the CA certificates that signed the agents' LDevID
  certificates, used for the proof-of-possession challenge.
- `endorsement_ca_path`: the TPM manufacturer CA certificates that signed the
  endorsement certificates, used for the proof-of-residency challenge.

For full configuration options, please refer to the
[Server `tpm_devid` plugin documentation](plugin_server_nodeattestor_tpm_devid.md).

#### Collecting manufacturer CA certificates

`endorsement_ca_path` is the one input to this deployment that SPIRE cannot
generate. Each TPM's endorsement certificate is issued by its manufacturer, so
the trust bundle has to be assembled from the vendors' published roots and
intermediates, and it must cover every TPM model in the fleet — a bundle that
omits one vendor rejects those nodes at the proof-of-residency step.

To determine what a given node needs, read its endorsement certificate and
inspect the issuer:

```shell
tpm2_nvread 0x1c00002 | openssl x509 -inform DER -noout -issuer -subject
```

Obtain the matching root and intermediate certificates from the manufacturer
named in the issuer — vendors publish these on their security or trust-anchor
pages — and concatenate all of them, across vendors, into the PEM file given to
`endorsement_ca_path`. Verify a node's certificate chains to the assembled
bundle before relying on it:

```shell
tpm2_nvread 0x1c00002 | openssl x509 -inform DER -out /tmp/ek.pem
openssl verify -CAfile endorsement_cas.pem /tmp/ek.pem
```

> [!NOTE]
> Some vendors issue endorsement certificates from intermediates that are not
> distributed with the root, and some provide the chain through an EK
> certificate service rather than as a file. Both cases still resolve to the
> same requirement: every certificate needed to build a path from the node's EK
> certificate to a trusted root must be present in the bundle.

### 3. SPIRE Agent Configuration

Configure the `tpm_devid` attestor in the SPIRE Agent configuration file
(`agent.conf`) to point to the LDevID certificate and key blobs provisioned
in Step 1.

If the owner hierarchy is protected, set `owner_hierarchy_password` to the same
value used during provisioning; the agent authorizes against that hierarchy each
time it recreates the primary key. Set `devid_password` as well if the DevID key
was created with one.

For full configuration details and a sample configuration block, please see
the [Agent `tpm_devid` plugin documentation](plugin_agent_nodeattestor_tpm_devid.md).

### 4. Node Aliases

On successful attestation the server always assigns the agent a SPIFFE ID
derived from its LDevID certificate fingerprint:

```xml
spiffe://<trust_domain>/spire/agent/tpm_devid/<fingerprint>
```

That identity is not configurable. Optionally, create a *node alias* — an
additional identity, shared by every node matching the given selectors — to use
as a stable `parentID` for workload entries. Without an alias, workload entries
must be parented to each node's fingerprint-based ID individually.

```shell
spire-server entry create \
  -spiffeID spiffe://example.org/node/primary \
  -node \
  -selector tpm_devid:subject:cn:node-01.example.org
```

The `tpm_devid` attestor produces `subject:cn:`, `issuer:cn:`, and
`ca:fingerprint:` selectors from the LDevID certificate chain.

## Scaling and Recovery

### Certificate Expiry or Node Re-imaging

If an agent's LDevID certificate expires or the node is wiped:

1. Re-provision the TPM by repeating [Section 1](#1-provisioning) to generate
   a new key pair and obtain a fresh certificate from the CA.
2. Replace the artifact files on disk (`devid.crt.pem`, `devid.pub.blob`,
   `devid.priv.blob`) with the new ones.
3. Restart the SPIRE Agent. It will re-attest using the new hardware-bound
   LDevID on its next connection to the server.
