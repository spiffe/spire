#!/usr/bin/env bash
# shellcheck shell=bash
##
## USAGE: __PROG__
##
## "__PROG__" publishes images to a registry.
##
## Usage example(s):
##   ./__PROG__ 1.5.2
##   ./__PROG__ v1.5.2
##   ./__PROG__ refs/tags/v1.5.2
##
## Commands
## - ./__PROG__ <version> pushes images to the registry using given version.

set -e

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

version="$1"
if [ -z "${version}" ]; then
  usage
  echo -e "\n Errors:\n * the version must be provided." >&2
  exit 1
fi

# remove the git tag prefix
# Push the images using the version tag (without the "v" prefix).
# Also strips the refs/tags part if the GITHUB_REF variable is used.
version="${version#refs/tags/v}"
version="${version#v}"

OCI_IMAGES=(
  spire-server spire-agent oidc-discovery-provider
)

org_name=$(echo "$GITHUB_REPOSITORY" | tr '/' "\n" | head -1 | tr -d "\n")
org_name="${org_name:-spiffe}" # default to spiffe in case ran on local
registry=ghcr.io/${org_name}

echo "Pushing images ${OCI_IMAGES[*]} to ${registry} with tag ${version}".
for img in "${OCI_IMAGES[@]}"; do
  oci_dir="ocidir://${ROOTDIR}oci/${img}"
  image_to_push="${registry}/${img}:${version}"
  
  regctl image import "${oci_dir}" "${img}-image.tar"
  regctl image copy "${oci_dir}" "${image_to_push}"

  image_digest="$(jq -r '.manifests[0].digest' "${ROOTDIR}oci/${img}/index.json")"

  cosign sign "${registry}/${img}@${image_digest}"
done
