# External CA HSM Suite

## Description

This suite tests the experimental external CA feature, which allows SPIRE Server to use an existing Certificate Authority from an HSM (Hardware Security Module) instead of generating its own intermediate CA.

The test:
1. Sets up SoftHSM as a test HSM
2. Generates a root CA and intermediate CA
3. Imports the intermediate CA private key into the HSM
4. Configures SPIRE Server to use the external CA
5. Verifies that workload X509-SVIDs can be issued correctly
6. Verifies that the X.509 CA remains static (does not rotate)
7. Verifies that JWT keys continue to rotate normally
8. Tests certificate validation (chain verification, key matching)

## Requirements

- SoftHSM2 package installed in the container
- OpenSSL for certificate generation
