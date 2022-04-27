#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)
BINDIR="${REPODIR}/bin"

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# change OS name to windows
if [[ "$OS" == msys_nt-10.0-* ]]; then
    OS=windows 
fi

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

EXTRAS_TARBALL="${OUTDIR}/spire-extras-${TAG}-${OS}-${ARCH}${LIBC}.tar.gz"
EXTRAS_CHECKSUM="${OUTDIR}/spire-extras-${TAG}-${OS}-${ARCH}${LIBC}_checksums.txt"

TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

STAGING="${TMPDIR}"/spire/spire-${TAG}
EXTRAS_STAGING="${TMPDIR}"/spire-extras/spire-extras-${TAG}
mkdir -p "${STAGING}" "${EXTRAS_STAGING}"

echo "Creating \"${TARBALL}\" and \"${EXTRAS_TARBALL}\""

# Copy in the contents under release/
cp -r release/spire-${OS}/* "${STAGING}"
cp -r release/spire-extras-${OS}/* "${EXTRAS_STAGING}"

# Copy in the LICENSE
cp "${REPODIR}"/LICENSE "${STAGING}"
cp "${REPODIR}"/LICENSE "${EXTRAS_STAGING}"

# Copy in the SPIRE binaries
mkdir -p "${STAGING}"/bin "${EXTRAS_STAGING}"/bin
cp "${BINDIR}"/spire-server "${STAGING}"/bin
cp "${BINDIR}"/spire-agent "${STAGING}"/bin
# Include registrar only for linux, until it is compatible with windows
if [ $OS == "linux" ]; then 
    cp "${BINDIR}"/k8s-workload-registrar "${EXTRAS_STAGING}"/bin
fi
cp "${BINDIR}"/oidc-discovery-provider "${EXTRAS_STAGING}"/bin

# Create the tarballs and checksums
mkdir -p "${OUTDIR}"
(cd "${TMPDIR}/spire"; tar -cvzf "${TARBALL}" "${TAROPTS[@]}" -- *)
(cd "${TMPDIR}/spire-extras"; tar -cvzf "${EXTRAS_TARBALL}" "${TAROPTS[@]}" -- *)

if [ $OS == "windows" ]; then 
    echo "$(CertUtil -hashfile "${TARBALL}" SHA256 | sed -n '2p') $(basename "${TARBALL}")" > "${CHECKSUM}"
    echo "$(CertUtil -hashfile "${EXTRAS_TARBALL}" SHA256 | sed -n '2p') $(basename "${EXTRAS_TARBALL}")" > "${EXTRAS_CHECKSUM}"
else 
    echo "$(shasum -a 256 "${TARBALL}" | cut -d' ' -f1) $(basename "${TARBALL}")" > "${CHECKSUM}"
    echo "$(shasum -a 256 "${EXTRAS_TARBALL}" | cut -d' ' -f1) $(basename "${EXTRAS_TARBALL}")" > "${EXTRAS_CHECKSUM}"
fi
