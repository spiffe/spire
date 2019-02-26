#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

bold=$(tput bold) || true
norm=$(tput sgr0) || true
red=$(tput setaf 1) || true
green=$(tput setaf 2) || true

# run in a separate namespace
if [ -z "$TRAVIS" ]; then
	MINIKUBECMD="minikube -p spire-k8s-tests"
else
	MINIKUBECMD="minikube"
fi

prestart() {
	# travis-only: mount root as rshared to fix an issue with kube-dns
	[ -z "$TRAVIS" ] || sudo mount --make-rshared /
}

verify_tools () {
	# check for kubectl
	if ! command -v kubectl > /dev/null; then
		[ -n "$TRAVIS" ] || fail "minikube is required."
		curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.13.2/bin/linux/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/
	fi

	# check for minikube
	if ! command -v minikube > /dev/null; then
		[ -n "$TRAVIS" ] || fail "kubectl is required."
		curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/
	fi

	# install the k8s-test binary
	( cd ${DIR}/../../tools/k8s-test && go install )
}

start_minikube() {
	# start minikube if it isn't already running
	if ! $MINIKUBECMD status > /dev/null; then
		if [ -n "$TRAVIS" ]; then
			sudo $MINIKUBECMD start --vm-driver=none --bootstrapper=kubeadm
		else
			$MINIKUBECMD start
		fi
	fi

	# update context
	$MINIKUBECMD update-context > /dev/null

	# wait for minikube to run
	JSONPATH='{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}'; until kubectl get nodes -o jsonpath="$JSONPATH" 2>&1 | grep -q "Ready=True"; do sleep 1; done
}

prestart
verify_tools
start_minikube

# add GOPATH/bin to the PATH
export PATH="$(go env GOPATH)"/bin:$PATH

for testdir in "${DIR}"/*; do
	if [ -d "${testdir}" ]; then
		testname=$(basename "$testdir")
		prefix="${bold}($testname)${norm}"
		echo "$prefix executing..."
		LOGPREFIX=$testname "$testdir"/test.sh && \
			echo "${prefix} ${green}success${norm}." || \
			echo "${prefix} ${red}failed${norm}."
	fi
done
