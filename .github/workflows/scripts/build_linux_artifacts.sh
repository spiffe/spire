#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

TARCMD=tar
if [[ $(uname -s) == "Darwin" ]]; then
    # When building linux artifacts from darwin, gtar is required.
    TARCMD="gtar"
fi

TAROPTS=("--owner=root" "--group=root")

TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT


copy_binary_from_multiarch_tar() {
    local arch=$1
    local binary=$2
    local destdir=$3

    local srcpath="/opt/spire/bin/${binary}"
    local destpath="${destdir}/${binary}"
    local ocidir="ocidir://${TMPDIR}/${arch}/oci/${binary}"
    local imagetar="${REPODIR}/${binary}-image.tar"
    local platform="linux/${arch}"

    echo "Importing multiarch image ${imagetar}..."
    regctl image import "${ocidir}" "${imagetar}"

    echo "Copying ${srcpath} for platform ${platform}..."
    regctl image get-file "${ocidir}" "${srcpath}" "${destpath}" -p "${platform}"

    # file does not retain permission bits, so fix up the executable bit.
    chmod +x "${destpath}"
}

build_artifact() {
    ARCH="$1"

    ARTIFACT="${OUTDIR}/spire-${TAG}-linux-${ARCH}-musl.tar.gz"
    CHECKSUM="${OUTDIR}/spire-${TAG}-linux-${ARCH}-musl_sha256sum.txt"

    EXTRAS_ARTIFACT="${OUTDIR}/spire-extras-${TAG}-linux-${ARCH}-musl.tar.gz"
    EXTRAS_CHECKSUM="${OUTDIR}/spire-extras-${TAG}-linux-${ARCH}-musl_sha256sum.txt"

    TARDIR="${TMPDIR}/${ARCH}/tar" 
    mkdir -p "${TARDIR}"

    STAGING="${TARDIR}"/spire/spire-${TAG}
    EXTRAS_STAGING="${TARDIR}"/spire-extras/spire-extras-${TAG}
    mkdir -p "${STAGING}" "${EXTRAS_STAGING}"

    echo "Creating \"${ARTIFACT}\" and \"${EXTRAS_ARTIFACT}\""

    # Copy in the contents under release/
    cp -r "${REPODIR}"/release/posix/spire/* "${STAGING}"
    cp -r "${REPODIR}"/release/posix/spire-extras/* "${EXTRAS_STAGING}"

    # Copy in the LICENSE
    cp "${REPODIR}"/LICENSE "${STAGING}"
    cp "${REPODIR}"/LICENSE "${EXTRAS_STAGING}"

    # Copy in the SPIRE binaries from the docker images:
    # 1. import the image from the multiarch tarball into the OCI directory
    mkdir -p "${STAGING}"/bin "${EXTRAS_STAGING}"/bin
    copy_binary_from_multiarch_tar "$ARCH" "spire-server" "${STAGING}/bin"
    copy_binary_from_multiarch_tar "$ARCH" "spire-agent" "${STAGING}/bin"
    copy_binary_from_multiarch_tar "$ARCH" "oidc-discovery-provider" "${EXTRAS_STAGING}/bin"

    mkdir -p "${OUTDIR}"

    # Create the tarballs and checksums
    (cd "${TARDIR}/spire"; ${TARCMD} -cvzf "${ARTIFACT}" "${TAROPTS[@]}" -- *)
    (cd "${TARDIR}/spire-extras"; ${TARCMD} -cvzf "${EXTRAS_ARTIFACT}" "${TAROPTS[@]}" -- *)

    (cd "$(dirname "${ARTIFACT}")"; shasum -a 256 "$(basename "${ARTIFACT}")" > "${CHECKSUM}" )
    (cd "$(dirname "${EXTRAS_ARTIFACT}")"; shasum -a 256 "$(basename "${EXTRAS_ARTIFACT}")" > "${EXTRAS_CHECKSUM}" )
}

command -v regctl >/dev/null 2>&1 || { echo -e "The regctl cli is required to run this script." >&2 ; exit 1; }
command -v "${TARCMD}" >/dev/null 2>&1 || { echo -e "The ${TARCMD} command is required to run this script." >&2 ; exit 1; }

build_artifact amd64
build_artifact arm64
