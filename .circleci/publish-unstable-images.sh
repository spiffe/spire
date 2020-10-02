#!/bin/bash

set -e

echo "Preparing to unstable images..."
echo "Branch : ${CIRCLE_BRANCH}"
echo "Tag    : ${CIRCLE_TAG}"
echo "Commit : ${CIRCLE_SHA1}"
echo
echo "Logging into gcr.io..."
docker login -u _json_key --password-stdin https://gcr.io <<< "$GCR_API_KEY"

# Push with commit tag
docker tag spire-server:latest-local gcr.io/spiffe-io/spire-server:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/spire-server:"${CIRCLE_SHA1}"
docker tag spire-agent:latest-local gcr.io/spiffe-io/spire-agent:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/spire-agent:"${CIRCLE_SHA1}"
docker tag k8s-workload-registrar:latest-local gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_SHA1}"
docker tag oidc-discovery-provider:latest-local gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_SHA1}"

# Also push with unstable tag
docker tag spire-server:latest-local gcr.io/spiffe-io/spire-server:unstable
docker push gcr.io/spiffe-io/spire-server:unstable
docker tag spire-agent:latest-local gcr.io/spiffe-io/spire-agent:unstable
docker push gcr.io/spiffe-io/spire-agent:unstable
docker tag k8s-workload-registrar:latest-local gcr.io/spiffe-io/k8s-workload-registrar:unstable
docker push gcr.io/spiffe-io/k8s-workload-registrar:unstable
docker tag oidc-discovery-provider:latest-local gcr.io/spiffe-io/oidc-discovery-provider:unstable
docker push gcr.io/spiffe-io/oidc-discovery-provider:unstable

