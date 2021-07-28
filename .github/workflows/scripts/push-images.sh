#!/bin/bash

set -e

IMAGETAG="$1"
if [ -z "$IMAGETAG" ]; then
    echo "IMAGETAG not provided!" 1>&2
    echo "Usage: push-images.sh IMAGETAG" 1>&2
    exit 1
fi

echo "Pushing images tagged as $IMAGETAG..."

for img in spire-server spire-agent k8s-workload-registrar oidc-discovery-provider; do
    gcrimg=gcr.io/spiffe-io/"$img":"${IMAGETAG}"
    echo "Executing: docker tag $img:latest-local $gcrimg"
    docker tag "$img":latest-local "$gcrimg"
    echo "Executing: docker push $gcrimg"
    docker push "$gcrimg"
done
