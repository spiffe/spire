#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -e

NUMRSA1024=5
NUMRSA2048=5
NUMRSA4096=5
NUMEC256=5
NUMEC384=5

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
