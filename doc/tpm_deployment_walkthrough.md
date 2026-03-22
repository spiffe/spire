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

Provision each node's TPM out-of-band. You'll need to generate a key pair in the TPM, get a certificate signed by your internal CA, and save the key blobs (`.priv` and `.pub`) to disk.

### 2. SPIRE Server Configuration

Configure the `tpm_devid` attestor in `server.conf`. Point to the CA that signed your node certificates.

```hcl
server {
    trust_domain = "example.org"
}

plugins {
    NodeAttestor "tpm_devid" {
        plugin_data {
            devid_ca_path = "/etc/spire/certs/devid-ca.pem"
            endorsement_ca_path = "/etc/spire/certs/tpm-manufacturer-ca.pem"
        }
    }
}
```

### 3. SPIRE Agent Configuration

Configure the `tpm_devid` attestor in `agent.conf`.

```hcl
agent {
    trust_domain = "example.org"
    server_address = "spire-control-plane.example.org"
    server_port = 8081
}

plugins {
    NodeAttestor "tpm_devid" {
        plugin_data {
            devid_cert_path = "/etc/spire/agent/devid.crt"
            devid_priv_path = "/etc/spire/agent/devid.priv"
            devid_pub_path = "/etc/spire/agent/devid.pub"
        }
    }
}
```

### 4. Node Registration

Create a registration entry for each node.

```shell
(in dev shell) # ./bin/spire-server entry create \
    -spiffeID spiffe://example.org/node/primary \
    -node \
    -selector tpm_devid:subject:cn:node-01.example.org
```

## Scaling and Recovery

**Horizontal Scaling**: Add server instances to the cluster by pointing them to the same datastore. Scale agents by provisioning new TPM-backed nodes.

**Trust Recovery**: If an agent's certificate expires or the node is wiped, re-provision the TPM and refresh the agent's identity. The agent will re-attest using the new hardware-bound DevID on its next cycle.
