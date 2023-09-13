#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)
BINDIR="${REPODIR}/bin"

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

ARCH=amd64

ARTIFACT="${OUTDIR}/spire-${TAG}-windows-${ARCH}.zip"
CHECKSUM="${OUTDIR}/spire-${TAG}-windows-${ARCH}_sha256sum.txt"

EXTRAS_ARTIFACT="${OUTDIR}/spire-extras-${TAG}-windows-${ARCH}.zip"
EXTRAS_CHECKSUM="${OUTDIR}/spire-extras-${TAG}-windows-${ARCH}_sha256sum.txt"

TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

STAGING="${TMPDIR}"/spire/spire-${TAG}
EXTRAS_STAGING="${TMPDIR}"/spire-extras/spire-extras-${TAG}
mkdir -p "${STAGING}" "${EXTRAS_STAGING}"

echo "Creating \"${ARTIFACT}\" and \"${EXTRAS_ARTIFACT}\""

# Copy in the contents under release/
cp -r "${REPODIR}"/release/windows/spire/* "${STAGING}"
cp -r "${REPODIR}"/release/windows/spire-extras/* "${EXTRAS_STAGING}"

# Copy in the LICENSE
cp "${REPODIR}"/LICENSE "${STAGING}"
cp "${REPODIR}"/LICENSE "${EXTRAS_STAGING}"

# Copy in the SPIRE binaries
mkdir -p "${STAGING}"/bin "${EXTRAS_STAGING}"/bin
cp "${BINDIR}"/spire-server.exe "${STAGING}"/bin
cp "${BINDIR}"/spire-agent.exe "${STAGING}"/bin
cp "${BINDIR}"/oidc-discovery-provider.exe "${EXTRAS_STAGING}"/bin

mkdir -p "${OUTDIR}"

(cd "${TMPDIR}/spire"; zip -rv "${ARTIFACT}" -- *)
(cd "${TMPDIR}/spire-extras"; zip -rv "${EXTRAS_ARTIFACT}" -- *)

(cd "$(dirname "${ARTIFACT}")"; CertUtil -hashfile "$(basename "${ARTIFACT}")" SHA256 > "${CHECKSUM}")
(cd "$(dirname "${EXTRAS_ARTIFACT}")"; CertUtil -hashfile "$(basename "${EXTRAS_ARTIFACT}")" SHA256 > "${EXTRAS_CHECKSUM}")
