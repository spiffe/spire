# Force rotation with JWT Authority Test Suite

## Description

This test suite configures a single SPIRE Server and Agent to validate the forced rotation and revocation of JWT authorities.

## Test steps

1. **Prepare a new JWT authority**: Verify that a new JWT authority is successfully created.
2. **Activate the new JWT authority**: Ensure that the new JWT authority becomes the active authority.
3. **Taint the old JWT authority**: Confirm that the old JWT authority is marked as tainted, and verify that the taint instruction is propagated to the agent, triggering the deletion of any JWT-SVID signed by tainted authority.
4. **Revoke the tainted JWT authority**: Validate that the revocation instruction is propagated to the agent and that all the JWT-SVIDs have the revoked authority removed.
