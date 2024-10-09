# Force rotation with Upstream Authority Test Suite

## Description

This test suite configures a disk-based Upstream Authority to validate the forced rotation and revocation of X.509 authorities.

## Test steps

1. **Prepare a new X.509 authority**: Verify that a new X.509 authority is successfully created.
2. **Activate the new X.509 authority**: Ensure that the new X.509 authority becomes the active authority.
3. **Taint the old X.509 authority**: Confirm that the old X.509 authority is marked as tainted, and verify that the taint instruction is propagated to the agent, triggering the rotation of all X.509 SVIDs.
4. **Revoke the tainted X.509 authority**: Validate that the revocation instruction is propagated to the agent and that all the SVIDs have the revoked authority removed.
