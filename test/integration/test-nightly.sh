#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Nightly tests are done against the latest non-local images
/usr/bin/env \
    SPIRE_SERVER_IMAGE=gcr.io/spiffe-io/spire-server:unstable \
    SPIRE_AGENT_IMAGE=gcr.io/spiffe-io/spire-agent:unstable \
    "${DIR}/test-all.sh"
