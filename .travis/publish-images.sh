#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Preparing to build and push images..."
echo "Travis Branch : ${TRAVIS_BRANCH}"
echo "Travis Tag    : ${TRAVIS_TAG}"
echo "Travis Commit : ${TRAVIS_COMMIT}"

# Strip the leading "v" off of the tag name if this is a version tag (e.g.
# v0.9.3). SPIRE images are tagged with just the version number.
if [[ "${TRAVIS_TAG}" =~ v[0-9.]+ ]]; then
    TRAVIS_TAG=${TRAVIS_TAG##v}
fi

# Log in to gcr.io using a key file for the Travis CI service account. The key
# file is NOT stored plaintext and is decrypted by Travis CI before this script
# is run.
echo "Logging into gcr.io..."
docker login -u _json_key --password-stdin https://gcr.io < "${DIR}/spire-travis-ci.json"

# Tag and push latest build by Git hash
docker tag spire-server gcr.io/spiffe-io/spire-server:"${TRAVIS_COMMIT}"
docker push gcr.io/spiffe-io/spire-server:"${TRAVIS_COMMIT}"
docker tag spire-agent gcr.io/spiffe-io/spire-agent:"${TRAVIS_COMMIT}"
docker push gcr.io/spiffe-io/spire-agent:"${TRAVIS_COMMIT}"
docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:"${TRAVIS_COMMIT}"
docker push gcr.io/spiffe-io/k8s-workload-registrar:"${TRAVIS_COMMIT}"
docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:"${TRAVIS_COMMIT}"
docker push gcr.io/spiffe-io/oidc-discovery-provider:"${TRAVIS_COMMIT}"

if [ -n "${TRAVIS_TAG}" ]; then
	# This is a tagged build. Tag and push under the git tag.
	docker tag spire-server gcr.io/spiffe-io/spire-server:"${TRAVIS_TAG}"
	docker push gcr.io/spiffe-io/spire-server:"${TRAVIS_TAG}"
	docker tag spire-agent gcr.io/spiffe-io/spire-agent:"${TRAVIS_TAG}"
	docker push gcr.io/spiffe-io/spire-agent:"${TRAVIS_TAG}"
	docker tag k8s-workload-registrar gcr.io/spiffe-io/k8s-workload-registrar:"${TRAVIS_TAG}"
	docker push gcr.io/spiffe-io/k8s-workload-registrar:"${TRAVIS_TAG}"
	docker tag oidc-discovery-provider gcr.io/spiffe-io/oidc-discovery-provider:"${TRAVIS_TAG}"
	docker push gcr.io/spiffe-io/oidc-discovery-provider:"${TRAVIS_TAG}"
elif [ x"${TRAVIS_BRANCH}" = x"master" ]; then
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
