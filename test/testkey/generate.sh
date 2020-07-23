#!/bin/bash

# generate.sh - regenerate the test keys
#
# This script regenerates the test keys used by unit tests. It should be
# run when the number of keys used to test a package exceeds the number of
# pregenerated keys for that type.

# The following variables control how many keys of each type are generated:
NUMRSA1024=5
NUMRSA2048=5
NUMRSA4096=5
NUMEC256=15
NUMEC384=5

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -e

cd "${DIR}"

cleanup() {
    rm -f keys.go.tmp
}

go run genkeys.go \
    -rsa1024="${NUMRSA1024}" \
    -rsa2048="${NUMRSA2048}" \
    -rsa4096="${NUMRSA4096}" \
    -ec256="${NUMEC256}" \
    -ec384="${NUMEC384}" > keys.go.tmp

mv keys.go.tmp keys.go
