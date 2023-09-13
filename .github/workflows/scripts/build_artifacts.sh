#!/bin/bash
# Builds all SPIRE artifacts for all supported architectures for the provided operating system.
# Usage: build_artifacts.sh <Linux|Windows|macOS>

set -e

usage() {
    echo "usage: ${BASH_SOURCE[0]} <Linux|Windows>"
    exit 1
}

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export TAG=
if [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9.]+$ ]]; then
    # Strip off the leading "v" from the release tag. Release artifacts are
    # named just with the version number (e.g. v0.9.3 tag produces
    # spire-0.9.3-linux-x64.tar.gz).
    TAG="${GITHUB_REF##refs/tags/v}"
fi

[[ $# -eq 1 ]] || usage

os="$1"
case "${os}" in
    Linux)
        "${SCRIPTDIR}"/build_linux_artifacts.sh
        ;;
    Windows)
        "${SCRIPTDIR}"/build_windows_artifacts.sh
        ;;
    *)
        echo "Only artifacts for Linux and Windows are supported" 1>&2
        usage
        ;;
esac
