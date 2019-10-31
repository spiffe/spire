# Integration Test Framework

This directory contains the Integration Test framework for SPIRE. Integration
tests are run nightly or after there has been a merge into the master branch.

## Executing Test Suites

When the framework executes a test suite, it performs the following:

1. Creates a temporary directory.
1. Copies the contents of the test suite into the temporary directory.
1. Executes scripts that match the `??-*` pattern, ordered lexographically,
   where `??` is a "step number" (i.e. `00-setup`, `01-do-a-thing`).
1. The `teardown` script is executed. Note that the `teardown` script is
   **ALWAYS** executed when the test suite is torn down, independent of test
   suite success/failure. The `teardown` script **MUST** exist or the test will
   not be executed.
1. Temporary directory is removed.

In order for the test to pass, each step script must return a zero status code.

If a step script fails by exiting with a non-zero status code, the test suite
fails and execution moves immediately to the `teardown` script. Subsequent step
scripts are **NOT** executed.

## Adding a Test Suite

1. Create a new folder under `suites/`.
1. Add a `README.md` to the test suite and link to it in this document under
   [Test Suites](#test-suites). The README should contain high level details
   about what is being tested by the test suite.
1. Add step scripts (i.e. files matching the `??-*` pattern) that perform the
   requisite steps. These scripts will be executed in lexographic order.
1. Add a `teardown` script that cleans up after the test suite

### Step Scripts

Step scripts are sourced into a subshell with `set -e -o pipefail` set. The
functions within [common](./common) are also sourced into the subshell and
are available for use within the step script.

The working directory of the step script is the temporary directory prepared
for the test suite.

The step script should exit with a non-zero status code if the step fails in
order to trigger test suite failure.

The following environment variables are available to the step scripts:

| Environment Variable  | Description |
| --------- | ----------------|
| `REPODIR` | Path to the root of the git repository.          |
| `ROOTDIR` | Path to the root of the integration test directory (i.e. `${REPODIR}/test/integration` ) |

### Teardown Script

The `teardown` script should clean up anything set up by the step scripts (i.e.
stop docker containers, etc). It can also optionally log helpful information
when a test suite has failed to aid debuggability.

The working directory of the step script is the temporary directory prepared
for the test suite.

The following environment variables are available to the teardown script:

| Environment Variable  | Description |
| --------- | ----------------|
| `REPODIR` | Path to the root of the git repository.          |
| `ROOTDIR` | Path to the root of the integration test directory (i.e. `${REPODIR}/test/integration` ) |
| `SUCCESS` | If set, indicates the test suite was successful. |

## Test suites

* [Datastore (MySQL)](suites/datastore-mysql/README.md)
* [Datastore (Postgres)](suites/datastore-postgres/README.md)
* [Envoy SDS](suites/envoy-sds/README.md)
* [Ghostunnel + Federation](suites/ghostunnel-federation/README.md)
* [Join Token](suites/join-token/README.md)
* [Kubernetes](suites/k8s/README.md)
* [Rotation](suites/rotation/README.md)
* [Upgrade](suites/upgrade/README.md)
