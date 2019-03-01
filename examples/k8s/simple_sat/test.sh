#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cleanup() {
	# cleans the test environment (deletes the spire namespace)
	k8s-test clean
}
trap cleanup EXIT

# initialize the test environment (creates a clean spire namespace)
k8s-test init

# apply the server configuration first (and waits until it is ready)
k8s-test apply "${DIR}"/server*.yaml

# apply the agent configuration first (and waits until it is ready)
k8s-test apply "${DIR}"/agent*.yaml

# wait for a node to attest
k8s-test wait node-attestation deployment/spire-server
