#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

bold=$(tput bold) || true
norm=$(tput sgr0) || true
red=$(tput setaf 1) || true
green=$(tput setaf 2) || true

fail() {
	echo "${red}$*${norm}."
	exit 1
}

cp-stdin-to-minikube () {
	ssh \
		-i $(minikube ssh-key) \
        -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null \
		docker@$(minikube ip) \
		-- bash -c "cat - | sudo tee $1 > /dev/null"
}

echo "${bold}Checking for kubectl...${norm}"
command -v kubectl > /dev/null || fail "kubectl is required."

echo "${bold}Checking minikube status...${norm}"
minikube status || fail "minikube isn't running"

echo "${bold}Injecting admission controller credentials...${norm}"
minikube ssh -- sudo mkdir -p /var/lib/spire
cat admctrl-admission-control.yaml | cp-stdin-to-minikube /var/lib/spire/admission-control.yaml
cat admctrl-kubeconfig.yaml | cp-stdin-to-minikube /var/lib/spire/kubeconfig.yaml
minikube ssh -- sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml | \
	go run patch-manifest.go | \
	cp-stdin-to-minikube /etc/kubernetes/manifests/kube-apiserver.yaml

# Build the k8s-test binary and add it to the PATH
echo "${bold}Installing k8s-test...${norm}"
( cd "${DIR}"/../../tools/k8s-test && GO111MODULE=on go install ) || fail "unable to build k8s-test"
PATH="$(go env GOPATH)"/bin:$PATH
export PATH


cleanup() {
	k8s-test clean
}

trap cleanup EXIT

echo "${bold}Running test...${norm}"

k8s-test init
k8s-test apply "${DIR}"/spire-database.yaml
k8s-test apply "${DIR}"/spire-server.yaml
k8s-test apply "${DIR}"/spire-agent.yaml
k8s-test apply "${DIR}"/workload.yaml

k8s-test wait workload-creds example-workload- spiffe://example.org/ns/spire/sa/default

echo "${bold}Done.${norm}"
