#!/bin/bash

set -e

# Strip off the leading "v" from the release tag. Release artifacts are
# named just with the version number (e.g. v0.9.3 tag produces
# spire-0.9.3-linux-x64.tar.gz).
TAG="${CIRCLE_TAG##v}" make artifact
