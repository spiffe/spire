#!/usr/bin/env bash
# shellcheck shell=bash
##
## USAGE: __PROG__
##
## "__PROG__" loads oci tarballs created with xbuild into docker.
##
## Usage example(s):
##   ./__PROG__
##   PLATFORM=linux/arm64 ./__PROG__
##
## Commands
## - ./__PROG__ loads the oci tarball into Docker.

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

# Takes the current platform architecture or plaftorm as defined externally in a platform variable.
# e.g.:
# linux/amd64
# linux/arm64
# linux/arm64/v7
PLATFORM="${PLATFORM:-local}"
OCI_IMAGES=(
    spire-server spire-agent oidc-discovery-provider
)

echo "Importing ${OCI_IMAGES[*]} into docker".
for img in "${OCI_IMAGES[@]}"; do
    oci_dir="ocidir://${ROOTDIR}oci/${img}"
    platform_tar="${img}-${PLATFORM}-image.tar"
    
    # regclient works with directories rather than tars, so import the OCI tar to a directory
    regctl image import "$oci_dir" "${img}-image.tar"
    dig="$(regctl image digest --platform "$PLATFORM" "$oci_dir")"
    # export the single platform image using the digest
    regctl image export "$oci_dir@${dig}" "${platform_tar}"
    
    docker load < "${platform_tar}"
    docker image tag "localhost/oci/${img}:latest" "${img}:latest-local"
    docker image rm "localhost/oci/${img}:latest"
done
