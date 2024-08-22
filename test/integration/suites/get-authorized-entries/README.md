# Integration Test Suite: Get Authorized Entries

This test suite validates the functionality of getting authorized entries from the SPIRE server. It includes setup, execution, and cleanup of the test environment.

## Overview

The "Get Authorized Entries" test suite ensures that the SPIRE server and agent are correctly configured to handle and authorize entries. The suite involves setting up SPIRE, creating registration entries, running the test, and cleaning up after the test.

## Test Steps

1. **Setup (`01-setup.sh`)**
    - Generates required certificates and keys.
    - Starts the SPIRE server and agent.

2. **Create Registration (`02-create_registration.sh`)**
    - Creates necessary registration entries for testing.

3. **Assert Entities Creation (`03-assert-entities-created.sh`)**
   - Creates necessary registration entries for testing.

4. **Teardown (`teardown`)**
    - Stops the SPIRE server and agent.
    - Cleans up any remaining artifacts.

## Prerequisites

- Ensure you have SPIRE installed and configured.
- The `spire-server` and `spire-agent` binaries should be in your `PATH`.
- Ensure Docker and Rancher are installed if applicable for your environment.

## Running the Tests

1. **Run the Test Suite**

   To execute the test suite, run the following command:

   ```bash
   ./test/integration/test-one.sh ./test/integration/suites/get-authorized-entries\
