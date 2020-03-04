#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

TAG="$(git describe --abbrev=0 --match "v[0-9]*" 2>/dev/null || true)"
ALWAYS="$(git describe --always --match "v[0-9]*" || true)"
if [ "$TAG" == "$ALWAYS" ]; then
    # Strip off the leading "v" from the release tag. Release artifacts are
    # named just with the version number (e.g. v0.9.3 tag produces
    # spire-0.9.3-linux-x64.tar.gz).`
    TAG=${TAG##v}
    make -C "${DIR}/.." TAG="${TAG}" OUTDIR=./releases artifact
fi
