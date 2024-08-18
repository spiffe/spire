# Batchx509SVID RPC Integration Test

## Overview

This test ensures the continued operation of the `Batchx509SVID` RPC in Open Source SPIRE.

## Test Steps

1. **Setup**

    - Starts SPIRE server and agent.
    - Configures necessary registration entries.

   Run the setup script:

   ```bash
   sudo ./test/integration/suites/batchx509svid/01-setup.sh