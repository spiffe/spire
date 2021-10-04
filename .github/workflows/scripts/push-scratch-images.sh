#!/bin/bash

set -e

IMAGETAG="$1"
if [ -z "$IMAGETAG" ]; then
    echo "IMAGETAG not provided!" 1>&2
    echo "Usage: push-images.sh IMAGETAG" 1>&2
    exit 1
fi

# Extracting org name rather than hardcoding allows this
# action to be portable across forks
ORGNAME=$(echo "$GITHUB_REPOSITORY" | tr '/' "\n" | head -1 | tr -d "\n")

echo "Pushing images tagged as $IMAGETAG..."

for img in spire-server spire-agent oidc-discovery-provider; do
    ghcrimg="ghcr.io/${ORGNAME}/${img}:${IMAGETAG}"

    # Detect the oidc image and give it a different name for GHCR
    # TODO: Remove this hack and fully rename the image once we move
    # off of GCR.
    if [ "$img" == "oidc-discovery-provider" ]; then
            ghcrimg="ghcr.io/${ORGNAME}/spire-oidc-provider:${IMAGETAG}"
    fi

    echo "Executing: docker tag $img-scratch:latest-local $ghcrimg"
    docker tag "$img"-scratch:latest-local "$ghcrimg"
    echo "Executing: docker push $ghcrimg"
    docker push "$ghcrimg"
done
