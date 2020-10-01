#!/bin/bash

set -e

echo "Preparing to push release images..."
echo "Branch : ${CIRCLE_BRANCH}"
echo "Tag    : ${CIRCLE_TAG}"
echo "Commit : ${CIRCLE_SHA1}"
echo
echo "Logging into gcr.io..."
docker login -u _json_key --password-stdin https://gcr.io < echo "$GCR_API_KEY"

# Strip the leading "v" off of the tag name. SPIRE images are
# tagged with just the version number.
TAG=${CIRCLE_TAG##v}

docker tag spire-server gcr.io/spiffe-io/spire-server:"${TAG}"
docker push gcr.io/spiffe-io/spire-server:"${TAG}"
docker tag spire-agent gcr.io/spiffe-io/spire-agent:"${TAG}"
docker push gcr.io/spiffe-io/spire-agent:"${TAG}"
docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:"${TAG}"
docker push gcr.io/spiffe-io/k8s-workload-registrar:"${TAG}"
docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:"${TAG}"
docker push gcr.io/spiffe-io/oidc-discovery-provider:"${TAG}"

