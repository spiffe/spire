# Batchx509SVID RPC Integration Test

## Overview

This test ensures the continued operation of the `Batchx509SVID` RPC in Open Source SPIRE.

## Test Steps

1. **Setup (`01-setup.sh`)**
   - Generates required certificates and keys.
   - Starts the SPIRE server and agent.

2. **Create Registration (`02-create_entries.sh`)**
   - Creates necessary registration entries for testing.

2. **Check entries creation (`03-test-batchx509svid.sh`)**
   - Creates necessary registration entries for testing.

3. **Teardown (`teardown.sh`)**
- Stops the SPIRE server and agent.
- Cleans up any remaining artifacts.

   Run the setup script:

   ```bash
   ./test/integration/test-one.sh ./test/integration/suites/batchx509SVID
