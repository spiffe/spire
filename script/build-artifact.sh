#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)
BINDIR="${REPODIR}/bin"

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# handle the case that we're building for alpine
if [ "$OS" = "linux" ]; then
    case $(ldd --version 2>&1) in
        *GLIB*) LIBC="-glibc" ;;
        *muslr*) LIBC="-musl" ;;
        *) LIBC="-unknown" ;;
    esac
    TAROPTS=("--owner=root" "--group=root")
fi

TARBALL="${OUTDIR}/spire-${TAG}-${OS}-${ARCH}${LIBC}.tar.gz"
CHECKSUM="${OUTDIR}/spire-${TAG}-${OS}-${ARCH}${LIBC}_checksums.txt"

TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

STAGING="${TMPDIR}"/spire-${TAG}
mkdir "${STAGING}"

echo "Creating \"${TARBALL}\""

# Copy in the contents under release/
cp -r release/* "${STAGING}"

# Copy in the LICENSE
cp "${REPODIR}"/LICENSE "${STAGING}"

# Copy in the SPIRE binaries
mkdir -p "${STAGING}"/bin
cp "${BINDIR}"/spire-server "${STAGING}"/bin
cp "${BINDIR}"/spire-agent "${STAGING}"/bin

# Create the tarball and checksum
mkdir -p "${OUTDIR}"
tar -cvzf "${TARBALL}" --directory "${TMPDIR}" "${TAROPTS[@]}" .
echo "$(shasum -a 256 "${TARBALL}" | cut -d' ' -f1) $(basename "${TARBALL}")" > "$CHECKSUM"
