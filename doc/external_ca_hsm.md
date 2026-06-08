# Using an External CA with HSM (Experimental)

This document describes how to configure SPIRE Server to use an existing Certificate Authority (CA) from a Hardware Security Module (HSM) instead of generating its own intermediate CA.

## Overview

By default, SPIRE Server generates and manages its own X.509 intermediate CA, rotating it automatically according to configured TTLs. However, in some enterprise environments, organizations need to:

- Use existing PKI infrastructure
- Store CA keys in Hardware Security Modules (HSMs) for enhanced security
- Maintain compliance with policies requiring hardware-backed key storage
- Integrate SPIRE into established certificate hierarchies

The External CA feature allows SPIRE Server to use a pre-existing intermediate CA certificate with its private key stored in an HSM, accessed via PKCS#11.

## How It Works

When external CA mode is enabled:

1. **X.509 CA**: SPIRE loads an existing intermediate CA certificate and uses the HSM for signing operations
2. **JWT Keys**: Continue to rotate normally using the configured key manager
3. **Trust Bundle**: Contains both the root CA and intermediate CA certificates
4. **Rotation**: X.509 CA rotation is disabled; the external CA remains static

## Architecture Changes

### Normal SPIRE CA Management
```
┌─────────────────────────────────────┐
│  SPIRE Server                       │
│  ┌────────────────────────────────┐ │
│  │  CA Manager                    │ │
│  │  - Generates Intermediate CA   │ │
│  │  - Rotates CA automatically    │ │
│  │  - Stores keys in KeyManager   │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### External CA Mode
```
┌─────────────────────────────────────┐
│  SPIRE Server                       │
│  ┌────────────────────────────────┐ │
│  │  CA Manager                    │ │
│  │  - Loads existing cert         │ │
│  │  - Uses HSM for signing        │ │
│  │  - No X.509 CA rotation        │ │
│  └────────────┬───────────────────┘ │
└────────────────┼─────────────────────┘
                 │ PKCS#11
                 ▼
        ┌──────────────────┐
        │  HSM             │
        │  - Stores CA key │
        │  - Signs SVIDs   │
        └──────────────────┘
```

## Configuration

### Prerequisites

1. **Root CA Certificate**: PEM-encoded root certificate
2. **Intermediate CA Certificate**: PEM-encoded intermediate certificate signed by the root
3. **HSM Access**: PKCS#11-accessible HSM with the intermediate CA private key
4. **PKCS#11 URI**: Connection details for the HSM

### Configuration Example

```hcl
server {
    trust_domain = "example.org"
    data_dir = "/opt/spire/data"

    experimental {
        external_ca {
            enabled = true
            root_cert_file_path = "/opt/spire/conf/root-ca.pem"
            cert_file_path = "/opt/spire/conf/intermediate-ca.pem"
            pkcs11 {
                pkcs11_uri = "pkcs11:token=MyHSM;pin-value=1234"
                pkcs11_object = "spire-intermediate-key"
            }
        }
    }
}
...
```

### Configuration Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `enabled` | Enable external CA mode | Yes |
| `root_cert_file_path` | Path to root CA certificate (PEM) | Yes |
| `cert_file_path` | Path to intermediate CA certificate (PEM) | Yes |
| `pkcs11.pkcs11_uri` | PKCS#11 URI for HSM connection | Yes |
| `pkcs11.pkcs11_object` | Object name/ID of the private key in HSM | Yes |

### PKCS#11 URI Format

The PKCS#11 URI should follow the format:
```
pkcs11:token=<token-name>;pin-value=<pin>
```

Additional attributes can be included:
```
pkcs11:token=MyToken;slot-id=0;pin-value=1234
pkcs11:module-path=/usr/lib/softhsm/libsofthsm2.so;token=MyToken;pin-value=secret
```

Refer to [RFC 7512](https://tools.ietf.org/html/rfc7512) for complete URI specification.

## Certificate Requirements

### Root Certificate
- Must be a valid X.509 CA certificate
- Should have appropriate KeyUsage (keyCertSign, cRLSign)
- Must be trusted by all SPIRE components

### Intermediate Certificate
- Must be signed by the root certificate
- Must have `BasicConstraints: CA=TRUE`
- Must have appropriate KeyUsage (digitalSignature, keyCertSign, cRLSign)
- Public key must match the private key stored in the HSM
- Should have a validity period appropriate for your environment

### Validation Checks

SPIRE Server performs the following validations on startup:

1. **Chain Verification**: Verifies intermediate is signed by root
2. **CA Constraints**: Checks that intermediate has `CA:TRUE`
3. **Key Matching**: Verifies HSM key matches certificate public key

If any validation fails, SPIRE Server will not start and will log the specific error.

## Certificate Lifecycle

### Initial Setup

1. Generate or obtain root and intermediate certificates from your PKI
2. Import the intermediate private key into your HSM
3. Configure SPIRE Server with paths to certificates and HSM details
4. Start SPIRE Server

### Certificate Renewal

When the intermediate certificate approaches expiration:

1. SPIRE logs a warning 30 days before expiration
2. Generate a new intermediate certificate with the same key
3. Update the `cert_file_path` to point to the new certificate
4. Restart SPIRE Server

**Important**: The private key in the HSM remains the same; only the certificate is renewed.

### Monitoring

Monitor the following:
- Certificate expiration dates
- HSM availability and connectivity
- SPIRE Server logs for expiration warnings

## Operational Considerations

### JWT Key Rotation

JWT keys continue to rotate normally using the configured KeyManager. This ensures JWT-SVIDs can be refreshed even though the X.509 CA is static.

### High Availability

For HA deployments:
- All SPIRE servers can either share an HSM (network) or use different ones so long as the root CA is shared
- Certificate files must be available on all nodes
- HSM must support concurrent access from multiple servers

### Backup and Recovery

**Critical**: The intermediate CA private key in the HSM is the root of trust. Ensure:
- HSM backup procedures are in place
- Recovery procedures are tested
- Certificate files are backed up
- PKCS#11 credentials are securely stored

### Performance

HSM signing operations may have different performance characteristics compared to software signing:
- Latency may be higher for each signing operation
- Throughput depends on HSM capabilities
- Consider HSM capacity when sizing your deployment

## Security Considerations

### Key Security
- The intermediate CA key never leaves the HSM
- All signing operations occur within the HSM
- PIN/credentials should be protected (consider using environment variables)

### Access Control
- Restrict file system access to certificate files
- Use HSM access controls to limit who can use the signing key
- Audit HSM access logs

### Credential Management
- **Do not** hardcode PINs in configuration files
- Use environment variable expansion: `pin-value=$HSM_PIN`
- Rotate HSM PINs according to your security policy

## Troubleshooting

### Common Issues

**Error: "intermediate CA certificate is not signed by root CA"**
- Verify the intermediate certificate is actually signed by the root
- Check that you're using the correct root certificate file
- Use `openssl verify` to validate the chain

**Error: "HSM signer public key does not match intermediate certificate public key"**
- The key in the HSM doesn't match the certificate
- Verify you're referencing the correct key object in the HSM
- Check the certificate was generated from the HSM key

**Error: "failed to initialize PKCS#11"**
- HSM is not accessible
- PKCS#11 URI is incorrect
- HSM driver/library not installed
- Check HSM connectivity and credentials

**Warning: "External CA certificate is approaching expiration"**
- Certificate expires in less than 30 days
- Renew the certificate soon
- No immediate action required, but plan renewal

### Debugging

Enable debug logging:
```hcl
server {
    log_level = "DEBUG"
}
```

Check logs for:
- Certificate loading messages
- HSM connection details
- Validation results
- Expiration warnings

### Testing HSM Connectivity

Before configuring SPIRE, test HSM access:
```bash
# List available tokens
pkcs11-tool --list-tokens

# List objects on a specific token
pkcs11-tool --token "MyToken" --login --list-objects

# Test signing operation
pkcs11-tool --token "MyToken" --login --sign --id <key-id>
```

## Limitations

- X.509 CA certificates must be renewed manually
- The feature is experimental and subject to change
- HSM must support PKCS#11
- Certificate chain validation is performed on startup only
- Root CA cannot be rotated without recreating the trust domain

## Example: Using SoftHSM for Testing

For testing purposes, you can use SoftHSM:

```bash
# Install SoftHSM
apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 5678

# Import private key
softhsm2-util --import intermediate-key.pem --slot 0 --label "spire-ca" --id 01 --pin 1234

# Configure SPIRE
pkcs11_uri = "pkcs11:module-path=/usr/lib/softhsm/libsofthsm2.so;token=TestToken;pin-value=1234"
pkcs11_object = "spire-ca"
```

**Warning**: SoftHSM provides no real security benefits and should only be used for testing.

## Further Reading

- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [RFC 7512: PKCS#11 URI](https://tools.ietf.org/html/rfc7512)
- [SPIRE Server Configuration Reference](/doc/spire_server.md)
- [X.509 Certificate and CRL Profile (RFC 5280)](https://tools.ietf.org/html/rfc5280)
