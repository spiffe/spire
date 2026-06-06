# TPM Deployment Walkthrough

This guide describes a redundant SPIRE deployment using TPM 2.0 for node
attestation in non-Kubernetes environments.

## Architecture

A production-ready setup consists of a high-availability SPIRE Server cluster
and agents running on hardware with TPM 2.0 support.

- **Control Plane**: Multiple servers sharing a SQL datastore (Postgres or
  MySQL) for persistence and HA.
- **Agent Nodes**: Physical or virtual infrastructure with `/dev/tpm0`
  available.
- **LDevID**: TPM-bound Local Device Identifiers provisioned out-of-band.

## Requirements

- **TPM 2.0 hardware**: Accessible via `/dev/tpm0`.
- **Pre-provisioned DevID**: Key blobs and certificates must be on-node before
  starting the agent.
- **Internal CA**: The CA that signed the LDevIDs must be trusted by the
  SPIRE Server.

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

**b. Create the LDevID signing key (fixed to the TPM — the private key never
leaves the hardware):**

```shell
tpm2_create \
  -C /tmp/primary.ctx \
  -G ecc:ecdsa-sha256 \
  -u /opt/spire/conf/agent/devid.pub.blob \
  -r /opt/spire/conf/agent/devid.priv.blob \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"
```

**c. Load the key, make it temporarily persistent, and generate a Certificate
Signing Request (CSR):**

```shell
tpm2_load \
  -C /tmp/primary.ctx \
  -u /opt/spire/conf/agent/devid.pub.blob \
  -r /opt/spire/conf/agent/devid.priv.blob \
  -c /tmp/devid.ctx

tpm2_evictcontrol -C o -c /tmp/devid.ctx 0x81000001

openssl req \
  -provider tpm2 \
  -provider default \
  -new \
  -key "handle:0x81000001" \
  -out /tmp/devid.csr \
  -subj "/CN=$(hostname -f)/O=Example Org"

tpm2_evictcontrol -C o -c 0x81000001
```

**d. Submit the CSR to your internal CA and store the signed certificate:**

The CA-specific signing step is out of scope here, but the returned certificate
should be placed at `/opt/spire/conf/agent/devid.crt.pem`. The three resulting
artifacts — `devid.crt.pem`, `devid.pub.blob`, and `devid.priv.blob` — are
what the SPIRE Agent configuration requires.

> [!NOTE]
> `/tmp/primary.ctx` and `/tmp/devid.ctx` are volatile TPM context handles
> used only during provisioning. They do not need to be retained after the
> CSR is signed.

These artifacts establish the initial hardware-bound identity that the SPIRE
Agent will use to attest to the Server.

### 2. SPIRE Server Configuration

Configure the `tpm_devid` attestor in the SPIRE Server configuration file
(`server.conf`). The server must be configured with a path to the CA
certificates (`devid_ca_path`) that signed the agents' LDevID certificates.

For full configuration options, including how to configure endorsement
verification, please refer to the
[Server `tpm_devid` plugin documentation](plugin_server_nodeattestor_tpm_devid.md).

### 3. SPIRE Agent Configuration

Configure the `tpm_devid` attestor in the SPIRE Agent configuration file
(`agent.conf`) to point to the LDevID certificate and key blobs provisioned
in Step 1.

For full configuration details and a sample configuration block, please see
the [Agent `tpm_devid` plugin documentation](plugin_agent_nodeattestor_tpm_devid.md).

### 4. Node Registration

Create a registration entry to map the node's TPM identity (e.g., the Common
Name in its LDevID certificate) to a specific SPIFFE ID.

This step is strictly optional. If omitted, the server will default to issuing
a SPIFFE ID based on the node's LDevID certificate fingerprint. However,
explicitly registering the node is recommended to assign a recognized,
human-readable SPIFFE ID (such as `spiffe://example.org/node/primary`) for
associating subsequent workload entries.

```shell
(in dev shell) # ./bin/spire-server entry create \
    -spiffeID spiffe://example.org/node/primary \
    -node \
    -selector tpm_devid:subject:cn:node-01.example.org
```

## Scaling and Recovery

**Horizontal Scaling**: Add server instances to the cluster by pointing them
to the same datastore. Scale agents by provisioning new TPM-backed nodes.

**Trust Recovery**: If an agent's certificate expires or the node is wiped,
re-provision the TPM and refresh the agent's identity. The agent will
re-attest using the new hardware-bound DevID on its next cycle.
