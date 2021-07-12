#!/bin/bash

set -e

export TAG=
if [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9.]+$ ]]; then
        # Strip off the leading "v" from the release tag. Release artifacts are
        # named just with the version number (e.g. v0.9.3 tag produces
        # spire-0.9.3-linux-x64.tar.gz).
        TAG="${GITHUB_REF##refs/tags/v}"
fi

# Make references the $TAG environment variable set above
make artifact
