#!/bin/bash
# Builds the SPIRE artifacts for the provided operating system. On Linux, the
# architectures to build default to all supported ones and can be narrowed
# with extra arguments.
# Usage: build_artifacts.sh <Linux|Windows> [arch...]

set -e

usage() {
    echo "usage: ${BASH_SOURCE[0]} <Linux|Windows> [arch...]"
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

[[ $# -ge 1 ]] || usage

os="$1"
shift
case "${os}" in
    Linux)
        "${SCRIPTDIR}"/build_linux_artifacts.sh "$@"
        ;;
    Windows)
        "${SCRIPTDIR}"/build_windows_artifacts.sh
        ;;
    *)
        echo "Only artifacts for Linux and Windows are supported" 1>&2
        usage
        ;;
esac
