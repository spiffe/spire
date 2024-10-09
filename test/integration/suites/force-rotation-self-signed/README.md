# Force rotation with selt-signed X.509 authority Suite

## Description

This test suite configures a self-signed CA in the root-server,
and exercises forced rotation of CA certificates across nested servers.
The integration test is structured with three layers of server/agents pairs:

                         root-server
                              |
                         root-agent
                        /           \
         intermediateA-server   intermediateA-server
                |                       |
         intermediateA-agent    intermediateA-agent
                |                       |
           leafA-server            leafA-server
                |                       |
           leafA-agent             leafA-agent

## Test steps

1. **Prepare a new X.509 authority**: Validate that the new X.509 authority is propagated to all nested servers.
2. **Activate the new X.509 authority**: Ensure that the new X.509 authority becomes active.
3. **Taint the old X.509 authority**: Confirm that the tainted authority is propagated to nested servers and that all X.509 SVIDs are rotated accordingly.
4. **Revoke the tainted X.509 authority**: Validate that the revocation instruction is propagated to all nested servers, and that all SVIDs have the revoked authority removed.
