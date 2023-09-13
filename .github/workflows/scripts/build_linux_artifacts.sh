#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

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
    local arch="$1"

    local artifact="${OUTDIR}/spire-${TAG}-linux-${arch}-musl.tar.gz"
    local checksum="${OUTDIR}/spire-${TAG}-linux-${arch}-musl_sha256sum.txt"

    local extras_artifact="${OUTDIR}/spire-extras-${TAG}-linux-${arch}-musl.tar.gz"
    local extras_checksum="${OUTDIR}/spire-extras-${TAG}-linux-${arch}-musl_sha256sum.txt"

    local tardir="${TMPDIR}/${arch}/tar" 
    local staging="${tardir}"/spire/spire-${TAG}
    local extras_staging="${tardir}"/spire-extras/spire-extras-${TAG}

    mkdir -p "${staging}"/bin 
    mkdir -p "${extras_staging}"/bin
    mkdir -p "${OUTDIR}"

    echo "Creating \"${artifact}\" and \"${extras_artifact}\""

    # Copy in the contents under release/
    cp -r "${REPODIR}"/release/posix/spire/* "${staging}"
    cp -r "${REPODIR}"/release/posix/spire-extras/* "${extras_staging}"

    # Copy in the LICENSE
    cp "${REPODIR}"/LICENSE "${staging}"
    cp "${REPODIR}"/LICENSE "${extras_staging}"

    # Copy in the SPIRE binaries from the docker images:
    # 1. import the image from the multiarch tarball into the OCI directory
    copy_binary_from_multiarch_tar "$arch" "spire-server" "${staging}/bin"
    copy_binary_from_multiarch_tar "$arch" "spire-agent" "${staging}/bin"
    copy_binary_from_multiarch_tar "$arch" "oidc-discovery-provider" "${extras_staging}/bin"

    # Create the tarballs and checksums
    (cd "${tardir}/spire"; tar -cvzf "${artifact}" "${TAROPTS[@]}" -- *)
    (cd "${tardir}/spire-extras"; tar -cvzf "${extras_artifact}" "${TAROPTS[@]}" -- *)

    (cd "$(dirname "${artifact}")"; shasum -a 256 "$(basename "${artifact}")" > "${checksum}" )
    (cd "$(dirname "${extras_artifact}")"; shasum -a 256 "$(basename "${extras_artifact}")" > "${extras_checksum}" )
}

command -v regctl >/dev/null 2>&1 || { echo -e "The regctl cli is required to run this script." >&2 ; exit 1; }

build_artifact amd64
build_artifact arm64
