#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)
BINDIR="${REPODIR}/bin"

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# change OS name to windows
if [[ "$OS" == msys_nt-10.0-* ]] || [[ "$OS" == mingw64_nt-10.0-* ]]; then
    OS=windows 
fi

# handle the case that we're building for alpine
if [ "$OS" = "linux" ]; then
    case $(ldd --version 2>&1) in
	*GNU\ libc*) LIBC="-glibc" ;;
        *GLIB*) LIBC="-glibc" ;;
        *muslr*) LIBC="-musl" ;;
        *) LIBC="-unknown" ;;
    esac
    TAROPTS=("--owner=root" "--group=root")
fi

ARTIFACT_EXTENSION=".tar.gz"
if [ ${OS} == "windows" ]; then
    ARTIFACT_EXTENSION=".zip"
    BINARY_EXTENSION=".exe"
fi

ARTIFACT="${OUTDIR}/spire-${TAG}-${OS}-${ARCH}${LIBC}${ARTIFACT_EXTENSION}"
EXTRAS_ARTIFACT="${OUTDIR}/spire-extras-${TAG}-${OS}-${ARCH}${LIBC}${ARTIFACT_EXTENSION}"


TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

STAGING="${TMPDIR}"/spire/spire-${TAG}
EXTRAS_STAGING="${TMPDIR}"/spire-extras/spire-extras-${TAG}
mkdir -p "${STAGING}" "${EXTRAS_STAGING}"

echo "Creating \"${ARTIFACT}\" and \"${EXTRAS_ARTIFACT}\""

# Use linux config file as default
RELEASE_FOLDER="posix"
if [ ${OS} == "windows" ]; then
    RELEASE_FOLDER="windows"
fi

# Copy in the contents under release/
cp -r release/${RELEASE_FOLDER}/spire/* "${STAGING}"
cp -r release/${RELEASE_FOLDER}/spire-extras/* "${EXTRAS_STAGING}"

# Copy in the LICENSE
cp "${REPODIR}"/LICENSE "${STAGING}"
cp "${REPODIR}"/LICENSE "${EXTRAS_STAGING}"

# Copy in the SPIRE binaries
mkdir -p "${STAGING}"/bin "${EXTRAS_STAGING}"/bin
cp "${BINDIR}"/spire-server${BINARY_EXTENSION} "${STAGING}"/bin
cp "${BINDIR}"/spire-agent${BINARY_EXTENSION} "${STAGING}"/bin
cp "${BINDIR}"/oidc-discovery-provider${BINARY_EXTENSION} "${EXTRAS_STAGING}"/bin

mkdir -p "${OUTDIR}"

function makeChecksum() {
	ALGORITHM=$1
	shift;
	ITEMS=( "$@" )

	CHECKSUM_FILE="${OUTDIR}/spire-${TAG}-${OS}-${ARCH}${LIBC}_${ALGORITHM}.txt"

	rm -f "${CHECKSUM_FILE}"
	touch "${CHECKSUM_FILE}"
	for ITEM in "${ITEMS[@]}"; do
		case ${ALGORITHM} in
			md5sum)    md5sum "${ITEM}" >> "${CHECKSUM_FILE}" ;;
			sha1sum)   shasum -a 1 "${ITEM}" >> "${CHECKSUM_FILE}" ;;
			sha224sum) shasum -a 224 "${ITEM}" >> "${CHECKSUM_FILE}" ;;
			sha256sum) shasum -a 256 "${ITEM}" >> "${CHECKSUM_FILE}" ;;
			sha512sum) shasum -a 512 "${ITEM}" >> "${CHECKSUM_FILE}" ;;
			*)         echo "Unsupported checksum ${ALGORITHM}"; exit 1 ;;
		esac
	done
}

if [ $OS == "windows" ]; then 
    (cd "${TMPDIR}/spire"; zip -rv "${ARTIFACT}" -- *)
    (cd "${TMPDIR}/spire-extras"; zip -rv "${EXTRAS_ARTIFACT}" -- *)

    makeChecksum sha256sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
else 
    # Create the tarballs and checksums
    (cd "${TMPDIR}/spire"; tar -cvzf "${ARTIFACT}" "${TAROPTS[@]}" -- *)
    (cd "${TMPDIR}/spire-extras"; tar -cvzf "${EXTRAS_ARTIFACT}" "${TAROPTS[@]}" -- *)

    makeChecksum md5sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
    makeChecksum sha1sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
    makeChecksum sha224sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
    makeChecksum sha256sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
    makeChecksum sha512sum "${ARTIFACT}" "${EXTRAS_ARTIFACT}"
fi
