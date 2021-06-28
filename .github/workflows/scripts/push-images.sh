#!/bin/bash

IMAGETAG="$1"
if [ -z "$IMAGETAG" ]; then
    echo "IMAGETAG not provided!" 1>&2
    echo "Usage: push-images.sh IMAGETAG" 1>&2
    exit 1
fi

for img in spire-server spire-agent k8s-workload-registrar oidc-discovery-provider; do
    gcrimg=gcr.io/spiffe-io/"$img":"${IMAGETAG}"
    docker tag "$img" "$gcrimg"
    docker push "$gcrimg"
done
