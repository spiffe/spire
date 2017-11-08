# Functional tests

This directory contains functional tests. These tests are executed in a Docker container.
In this container there are:

1. One SPIRE server
2. One SPIRE agent
3. Multiple workloads running in parallel
4. A tool that coordinates the workloads

Each workload simply requests an SVID and waits for its TTL to expire to request a new one and then repeats the loop.

## Stress tests

The objective is to test SPIRE under heavy load and make sure everything works as expected.

1. Try very short TTLs (<5 seconds)
2. Try a high number of workloads (100? 1000?)
3. Verify memory consumption (i.e. no leaks) and other resources
4. Verify API response time
5. Validate returned SVIDs (e.g. not expired)

## Configuration

You can adjust several parameters in file [functional/Makefile](/functional/Makefile):

|Configuration  | Description                                |
|---------------|--------------------------------------------|
|WORKLOADS      |  Number of workloads to run in parallel    |
|TIMEOUT        |  Total time in seconds the tests wil run   |
|TTL            |  TTL to use to register entries            |

## Execution

Functional tests are run with `make functional` in the root directory.
Upon completion the result of each workload can be seen. The test will fail if any workload failed.
