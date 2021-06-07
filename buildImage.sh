#! /bin/bash

VERSION=0.12.2


# make bin/k8s-workload-registrar

GIT_COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null)
GIT_REMOTE_URL=$(git config --get remote.origin.url 2>/dev/null)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BINARY_NAME="k8s-workload-registrar"
REPO="tsidentity"
IMAGE=$REPO/$BINARY_NAME:$GIT_COMMIT_SHA
MUTABLE_IMAGE=${REPO}/${BINARY_NAME}:${VERSION}



#docker build --build-arg goversion=1.16.3 --target k8s-workload-registrar -t k8s-workload-registrar -f Dockerfile.ms .
docker build --build-arg goversion=1.16.3 --target ${BINARY_NAME} -t ${IMAGE} -f Dockerfile.ms .
# docker build --no-cache -t $(IMAGE) .
docker tag ${IMAGE} ${MUTABLE_IMAGE}
# rm bin/${BINARY_NAME}
docker push ${IMAGE}
docker push ${MUTABLE_IMAGE}
