# Node Re-Attestation Suite

## Description

This suite tests the node re-attestation flow. It starts two spire agents, then evicts them to force the re-attestation flow.

Here we will use two spire agents:

- spire agent A is configured with the x509pop plugin, that allows the node re-attestation.
- spire agent B is configured with the join token plugin, with implements the TOFU security model and don't allow the node re-attestation.
