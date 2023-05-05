#!/bin/bash
# Builds all SPIRE artifacts for all supported architectures for the provided operating system.
# Usage: build_artifacts.sh <Linux|Windows|macOS>

set -e

usage() {
    echo "usage: ${BASH_SOURCE[0]} <Linux|Windows|macOS>"
    exit 1
}

[[ $# -eq 1 ]] || usage

os="$1"
declare -a supported_archs
if [[ "${os}" == "Linux" ]] || [[ "${os}" == "macOS" ]]; then
    supported_archs=(amd64 arm64)
elif [[ "${os}" == "Windows" ]]; then
    supported_archs=(amd64)
else
    echo "unrecognized OS: ${os}"
    usage
fi

export TAG=
if [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9.]+$ ]]; then
        # Strip off the leading "v" from the release tag. Release artifacts are
        # named just with the version number (e.g. v0.9.3 tag produces
        # spire-0.9.3-linux-x64.tar.gz).
        TAG="${GITHUB_REF##refs/tags/v}"
fi

# Make references the $TAG environment variable set above
for arch in "${supported_archs[@]}"; do
    GOARCH=$arch make artifact
done
