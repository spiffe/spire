#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Preparing to build and push images..."
echo "Branch : ${CIRCLE_BRANCH}"
echo "Tag    : ${CIRCLE_TAG}"
echo "Commit : ${CIRCLE_SHA1}"

# Log in to gcr.io using a key file for the Travis CI service account. The key
# file is NOT stored plaintext and is decrypted by Travis CI before this script
# is run.
echo "Logging into gcr.io..."
docker login -u _json_key --password-stdin https://gcr.io < "${DIR}/spire-travis-ci.json"

# Tag and push latest build by Git hash
docker tag spire-server gcr.io/spiffe-io/spire-server:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/spire-server:"${CIRCLE_SHA1}"
docker tag spire-agent gcr.io/spiffe-io/spire-agent:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/spire-agent:"${CIRCLE_SHA1}"
docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_SHA1}"
docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_SHA1}"
docker push gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_SHA1}"

if [ -n "${CIRCLE_TAG}" ]; then
	# This is a tagged build. Tag and push under the git tag.
	docker tag spire-server gcr.io/spiffe-io/spire-server:"${CIRCLE_TAG}"
	docker push gcr.io/spiffe-io/spire-server:"${CIRCLE_TAG}"
	docker tag spire-agent gcr.io/spiffe-io/spire-agent:"${CIRCLE_TAG}"
	docker push gcr.io/spiffe-io/spire-agent:"${CIRCLE_TAG}"
	docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_TAG}"
	docker push gcr.io/spiffe-io/k8s-workload-registrar:"${CIRCLE_TAG}"
	docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_TAG}"
	docker push gcr.io/spiffe-io/oidc-discovery-provider:"${CIRCLE_TAG}"
elif [ x"${CIRCLE_BRANCH}" = x"master" ]; then
	# This is an untagged build for master. Tag and push as unstable
	docker tag spire-server gcr.io/spiffe-io/spire-server:unstable
	docker push gcr.io/spiffe-io/spire-server:unstable
	docker tag spire-agent gcr.io/spiffe-io/spire-agent:unstable
	docker push gcr.io/spiffe-io/spire-agent:unstable
	docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:unstable
	docker push gcr.io/spiffe-io/k8s-workload-registrar:unstable
	docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:unstable
	docker push gcr.io/spiffe-io/oidc-discovery-provider:unstable
fi
