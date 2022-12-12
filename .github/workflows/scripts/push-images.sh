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
##   ./__PROG__ v1.5.2 -scratch
##   ./__PROG__ refs/tags/v1.5.2
##   ./__PROG__ refs/tags/v1.5.2 -scratch
##
## Commands
## - ./__PROG__ <version> [image-variant]   pushes images to the registry using given version.

set -e

function usage {
  grep '^##' "$0" | sed -e 's/^##//' -e "s/__PROG__/$me/" >&2
}

me=$(basename "$0")

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

variant="$2"
if [ -n "${variant}" ] && [ "${variant}" != "-scratch" ]; then
  usage
  echo -e "\n Errors:\n * The only supported variant is '-scratch'." >&2
  exit 1
fi

OCI_IMAGES=(
  spire-server spire-agent oidc-discovery-provider
)

registry=gcr.io/spiffe-io
if [ "${variant}" = "-scratch" ] ; then
  org_name=$(echo "$GITHUB_REPOSITORY" | tr '/' "\n" | head -1 | tr -d "\n")
  org_name="${org_name:-spiffe}" # default to spiffe in case ran on local
  registry=ghcr.io/${org_name}
else
  # Continue publishing the non-scratch k8s-workload-registrar to GCR
  OCI_IMAGES+=( k8s-workload-registrar )
fi

echo "Pushing images ${OCI_IMAGES[*]} to ${registry} with tag ${version}".
for img in "${OCI_IMAGES[@]}"; do
  image_variant="${img}${variant}"
  image_to_push="${registry}/${img}:${version}"
  docker tag "${image_variant}:latest-local" "${image_to_push}"
  docker push "${image_to_push}"
done
