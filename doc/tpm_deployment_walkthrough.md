# TPM Deployment Walkthrough

This guide describes a redundant SPIRE deployment using TPM 2.0 for node attestation in non-Kubernetes environments.

## Architecture

A production-ready setup consists of a high-availability SPIRE Server cluster and agents running on hardware with TPM 2.0 support.

- **Control Plane**: Multiple servers sharing a SQL datastore (Postgres or MySQL) for persistence and HA.
- **Agent Nodes**: Physical or virtual infrastructure with `/dev/tpm0` available.
- **LDevID**: TPM-bound Local Device Identifiers provisioned out-of-band.

## Requirements

- **TPM 2.0 hardware**: Accessible via `/dev/tpm0`.
- **Pre-provisioned DevID**: Key blobs and certificates must be on-node before starting the agent.
- **Internal CA**: The CA that signed the LDevIDs must be trusted by the SPIRE Server.

> [!TIP]
> Use `tpm2-tools` to verify TPM access and key residency before configuring the SPIRE plugin.

## Setup Walkthrough

### 1. Provisioning

Before configuring SPIRE, each node's TPM must be provisioned with a Local Device Identifier (LDevID) out-of-band. This process typically involves:

1. **Key Generation**: Using a tool like `tpm2-tools`, generate an asymmetric key pair securely within the TPM. The private portion of the key never leaves the hardware.
2. **Certificate Signing Request (CSR)**: Generate a CSR from the TPM key.
3. **Certificate Issuance**: Submit the CSR to your internal Certificate Authority (CA) to obtain the signed LDevID certificate for the node. 
4. **Storing Artifacts**: Securely store the returned certificate (`.pem` or `.crt`) alongside the generated key blobs (`.priv` and `.pub`) on the node's disk.

These artifacts establish the initial hardware-bound identity that the SPIRE Agent will use to attest to the Server.

### 2. SPIRE Server Configuration

Configure the `tpm_devid` attestor in the SPIRE Server configuration file (`server.conf`). The server must be configured with a path to the CA certificates (`devid_ca_path`) that signed the agents' LDevID certificates. 

For full configuration options, including how to configure endorsement verification, please refer to the [Server `tpm_devid` plugin documentation](plugin_server_nodeattestor_tpm_devid.md).

### 3. SPIRE Agent Configuration

Configure the `tpm_devid` attestor in the SPIRE Agent configuration file (`agent.conf`) to point to the LDevID certificate and key blobs provisioned in Step 1.

For full configuration details and a sample configuration block, please see the [Agent `tpm_devid` plugin documentation](plugin_agent_nodeattestor_tpm_devid.md).

### 4. Node Registration

Create a registration entry to map the node's TPM identity (e.g., the Common Name in its LDevID certificate) to a specific SPIFFE ID. 

This step is strictly optional. If omitted, the server will default to issuing a SPIFFE ID based on the node's LDevID certificate fingerprint. However, explicitly registering the node is recommended to assign a recognized, human-readable SPIFFE ID (such as `spiffe://example.org/node/primary`) for associating subsequent workload entries.

```shell
(in dev shell) # ./bin/spire-server entry create \
    -spiffeID spiffe://example.org/node/primary \
    -node \
    -selector tpm_devid:subject:cn:node-01.example.org
```

## Scaling and Recovery

**Horizontal Scaling**: Add server instances to the cluster by pointing them to the same datastore. Scale agents by provisioning new TPM-backed nodes.

**Trust Recovery**: If an agent's certificate expires or the node is wiped, re-provision the TPM and refresh the agent's identity. The agent will re-attest using the new hardware-bound DevID on its next cycle.
