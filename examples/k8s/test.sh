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

# Build the k8s-test binary and add it to the PATH
echo "${bold}Installing k8s-test...${norm}"
( cd "${DIR}"/../../tools/k8s-test && GO111MODULE=on go install ) || fail "unable to build k8s-test"
echo "${bold}Installing patch-manifest...${norm}"
( cd "${DIR}" && GO111MODULE=on go install patch-manifest.go ) || fail "unable to build patch-manifest"
PATH="$(go env GOPATH)"/bin:$PATH
export PATH


echo "${bold}Injecting admission controller credentials...${norm}"
if [ -n "${TRAVIS}" ]; then
    # travis runs minikube via driver=none, so commands should be
    # executed directly on the host...
    sudo mkdir -p /var/lib/spire
    sudo cp "${DIR}/admctrl-admission-control.yaml" /var/lib/spire/admission-control.yaml
    sudo cp "${DIR}/admctrl-kubeconfig.yaml" /var/lib/spire/kubeconfig.yaml
    sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml | patch-manifest | sudo tee /etc/kubernetes/manifests/kube-apiserver.yaml.tmp > /dev/null
    sudo mv /etc/kubernetes/manifests/kube-apiserver.yaml.tmp /etc/kubernetes/manifests/kube-apiserver.yaml
else
    minikube ssh -- sudo mkdir -p /var/lib/spire
    cat "${DIR}/admctrl-admission-control.yaml" | cp-stdin-to-minikube /var/lib/spire/admission-control.yaml
    cat "${DIR}/admctrl-kubeconfig.yaml" | cp-stdin-to-minikube /var/lib/spire/kubeconfig.yaml
    minikube ssh -- sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml | \
        patch-manifest | \
        cp-stdin-to-minikube /etc/kubernetes/manifests/kube-apiserver.yaml
fi

echo "${bold}Waiting for API server to restart...${norm}"
JSONPATH='{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}'; until kubectl get nodes -o jsonpath="$JSONPATH" 2>&1 | grep -q "Ready=True"; do sleep 1; done


cleanup() {
    if [ -z $DONE ]; then
       kubectl -nspire logs deployment/spire-server --all-containers || true
       kubectl -nspire logs daemonset/spire-agent --all-containers || true
       kubectl -nspire logs deployment/example-workload --all-containers || true
    fi
	k8s-test clean
}

wait-for-rollout() {
    ns=$1
    obj=$2
    for ((i=0; i<12; i++)); do
        if kubectl -n${ns} rollout status $obj --timeout=15s; then
            return
        fi
        kubectl -n${ns} describe pods
        kubectl -n${ns} logs --all-containers $obj || true
    done
    echo "${red}Failed waiting for ${obj} to roll out.${norm}" 1>&2
    exit 1
}

trap cleanup EXIT

echo "${bold}Running test...${norm}"

k8s-test init

kubectl create -f "${DIR}/k8s-workload-registrar-secret.yaml"

k8s-test apply --no-wait "${DIR}"/spire-database.yaml
wait-for-rollout spire statefulset/spire-database

k8s-test apply --no-wait "${DIR}"/spire-server.yaml
wait-for-rollout spire deployment/spire-server

k8s-test apply --no-wait "${DIR}"/spire-agent.yaml
wait-for-rollout spire daemonset/spire-agent

k8s-test apply --no-wait "${DIR}"/workload.yaml
wait-for-rollout spire deployment/example-workload

k8s-test wait workload-creds example-workload- spiffe://example.org/ns/spire/sa/default

DONE=1
echo "${bold}Done.${norm}"
