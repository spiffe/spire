#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

TAG="$(git describe --abbrev=0 --match "v[0-9]*" 2>/dev/null || true)"
ALWAYS="$(git describe --always --match "v[0-9]*" || true)"
if [ "$TAG" == "$ALWAYS" ]; then
    make -C "${DIR}/.." TAG="${TAG}" OUTDIR=./releases artifact
fi
