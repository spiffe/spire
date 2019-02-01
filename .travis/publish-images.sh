#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPODIR=${DIR}/..

echo "Preparing to build and push images..."
echo "Travis Branch : ${TRAVIS_BRANCH}"
echo "Travis Tag    : ${TRAVIS_TAG}"
echo "Travis Commit : ${TRAVIS_COMMIT}"

if [ x"${TRAVIS_EVENT_TYPE}" != x"push" ]; then
	echo "Skipping; only push builds are published"
	exit 0
fi

if [ -z "${TRAVIS_TAG}" ] && [ x"${TRAVIS_BRANCH}" != x"master" ]; then
	echo "Skipping; only tagged builds or builds off master are published"
	exit 0
fi

# Log in to gcr.io using a key file for the Travis CI service account. The key
# file is NOT stored plaintext and is decrypted by Travis CI before this script
# is run.
echo "Logging into gcr.io..."
cat "${DIR}/spire-travis-ci.json" | docker login -u _json_key --password-stdin https://gcr.io

# Build the SPIRE server and agent images
echo "Building images..."
make -C ${REPODIR} spire-images

# Tag and push latest build by Git hash
docker tag gcr.io/spiffe-io/spire-server:latest gcr.io/spiffe-io/spire-server:${TRAVIS_COMMIT}
docker push gcr.io/spiffe-io/spire-server:${TRAVIS_COMMIT}
docker tag gcr.io/spiffe-io/spire-agent:latest gcr.io/spiffe-io/spire-agent:${TRAVIS_COMMIT}
docker push gcr.io/spiffe-io/spire-agent:${TRAVIS_COMMIT}

if [ -n "${TRAVIS_TAG}" ]; then
	# This is a tagged build. Tag and push under the git tag.
	docker tag gcr.io/spiffe-io/spire-server:latest gcr.io/spiffe-io/spire-server:${TRAVIS_TAG}
	docker push gcr.io/spiffe-io/spire-server:${TRAVIS_TAG}
	docker tag gcr.io/spiffe-io/spire-agent:latest gcr.io/spiffe-io/spire-agent:${TRAVIS_TAG}
	docker push gcr.io/spiffe-io/spire-agent:${TRAVIS_TAG}
elif [ x"${TRAVIS_BRANCH}" = x"master" ]; then
	# This is an untagged build for master. Tag and push as unstable
	docker tag gcr.io/spiffe-io/spire-server:latest gcr.io/spiffe-io/spire-server:unstable
	docker push gcr.io/spiffe-io/spire-server:unstable
	docker tag gcr.io/spiffe-io/spire-agent:latest gcr.io/spiffe-io/spire-agent:unstable
	docker push gcr.io/spiffe-io/spire-agent:unstable
fi
