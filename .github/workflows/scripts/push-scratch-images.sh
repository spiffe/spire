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
ORGNAME=$(echo $GITHUB_REPOSITORY | tr '/' "\n" | head -1 | tr -d "\n")

echo "Pushing images tagged as $IMAGETAG..."

for img in spire-server spire-agent; do
    ghcrimg=ghcr.io/"$ORGNAME"/"$img":"${IMAGETAG}"
    echo "Executing: docker tag $img:latest-local $ghcrimg"
    docker tag "$img":latest-local "$ghcrimg"
    echo "Executing: docker push $ghcrimg"
    docker push "$ghcrimg"
done
