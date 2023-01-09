#!/usr/bin/env bash
# shellcheck shell=bash
##
## USAGE: __PROG__
##
## "__PROG__" loads oci tarballs created with xbuild into docker.
##
## Usage example(s):
##   ./__PROG__
##   ./__PROG__ -scratch
##   PLATFORM=linux/arm64 ./__PROG__ -scratch
##
## Commands
## - ./__PROG__ <image-variant>    loads the oci tarball for the optional variant into Docker.

function usage {
  grep '^##' "$0" | sed -e 's/^##//' -e "s/__PROG__/$me/" >&2
}

function normalize_path {
    # Remove all /./ sequences.
    local path=${1//\/.\//\/}
    local npath
    # Remove first dir/.. sequence.
    npath="${path//[^\/][^\/]*\/\.\.\//}"
    # Remove remaining dir/.. sequence.
    while [[ $npath != "$path" ]] ; do
        path=$npath
        npath="${path//[^\/][^\/]*\/\.\.\//}"
    done
    echo "$path"
}

me=$(basename "$0")
BASEDIR=$(dirname "$0")
ROOTDIR="$(normalize_path "$BASEDIR/../../../")"

command -v regctl >/dev/null 2>&1 || { usage; echo -e "\n * The regctl cli is required to run this script." >&2 ; exit 1; }
command -v docker >/dev/null 2>&1 || { usage; echo -e "\n * The docker cli is required to run this script." >&2 ; exit 1; }

variant="$1"

if [ -n "$variant" ] && [ "$variant" != "-scratch" ] ; then
    usage
    echo -e "The only supported variants are '-scratch'." >&2
    exit 1
fi

# Takes the current platform architecture or plaftorm as defined externally in a platform variable.
# e.g.:
# linux/amd64
# linux/arm64
# linux/arm64/v7
PLATFORM="${PLATFORM:-local}"
OCI_IMAGES=(
    spire-server spire-agent k8s-workload-registrar oidc-discovery-provider
)

echo "Importing ${OCI_IMAGES[*]} into docker".
for img in "${OCI_IMAGES[@]}"; do
    image_variant="${img}${variant}"
    oci_dir="ocidir://${ROOTDIR}oci/${image_variant}"
    platform_tar="${image_variant}-${PLATFORM}-image.tar"
    
    # regclient works with directories rather than tars, so import the OCI tar to a directory
    regctl image import "$oci_dir" "${image_variant}-image.tar"
    dig="$(regctl image digest --platform "$PLATFORM" "$oci_dir")"
    # export the single platform image using the digest
    regctl image export "$oci_dir@${dig}" "${platform_tar}"
    
    docker load < "${platform_tar}"
    docker image tag "localhost/oci/${image_variant}:latest" "${image_variant}:latest-local"
    docker image rm "localhost/oci/${image_variant}:latest"
done
