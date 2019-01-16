#!/bin/bash

set -e

bold=$(tput bold)
norm=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

MINIKUBEPROFILE="SPIRE-SYSTEMS-TEST"
MINIKUBECMD="minikube -p ${MINIKUBEPROFILE}"
CHECKINTERVAL=1
if [ -n "${TRAVIS}" ]; then
	# Use the default profile inside of Travis
	MINIKUBECMD="/usr/local/bin/minikube"
	# Travis is slow. Give our containers more time.
	CHECKINTERVAL=5
fi
TMPDIR=$(mktemp -d)
SERVERLOGS=${TMPDIR}/spire-server-logs.log

start_minikube() {
	# Travis will start up minikube (via .travis.yml)
	if [ -z "${TRAVIS}" ]; then
		echo "${bold}Starting minikube... ${norm}"
		${MINIKUBECMD} start
		eval $(${MINIKUBECMD} docker-env)
	fi
}

cleanup() {
	echo -n "${bold}Cleaning up... ${norm}"
	if [ ! -z "${SUCCESS}" ]; then
		# success. remove the tmp dir.
		rm -rf ${TMPDIR}
	fi
	kubectl delete daemonset spire-agent --namespace spire > /dev/null || true
	kubectl delete configmap spire-agent --namespace spire > /dev/null || true
	kubectl delete serviceaccount spire-agent --namespace spire > /dev/null || true
	kubectl delete deployment spire-server --namespace spire > /dev/null || true
	kubectl delete service spire-server --namespace spire > /dev/null || true
	kubectl delete configmap spire-server --namespace spire > /dev/null || true
	kubectl delete secrets spire-server --namespace spire > /dev/null || true
	kubectl delete serviceaccount spire-server --namespace spire > /dev/null || true
	kubectl delete namespace spire > /dev/null || true
	# Don't stop the minikube inside of travis
	if [ -z "${TRAVIS}" ]; then
		${MINIKUBECMD} stop > /dev/null || true
	fi
	echo "${green}ok${norm}."
}

# build the spire containers
make_containers() {
	echo -n "${bold}Making SPIRE containers... ${norm}"
	make -C ${DIR}/../../../ spire-containers > /dev/null
	echo "${green}done.${norm}"
}

# apply the k8s configuration
apply_server_config() {
	echo -n "${bold}Applying SPIRE server k8s configuration... ${norm}"
	kubectl apply -f ${DIR}/conf/spire-namespace.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/server-account.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/server-secrets.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/server-configmap.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/server-deployment.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/server-service.yaml > /dev/null
	echo "${green}ok.${norm}"
}

apply_agent_config() {
	echo -n "${bold}Applying SPIRE agent k8s configuration... ${norm}"
	kubectl apply -f ${DIR}/conf/agent-account.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/agent-configmap.yaml > /dev/null
	kubectl apply -f ${DIR}/conf/agent-daemonset.yaml > /dev/null
	echo "${green}ok.${norm}"
}

wait_for_pod() {
	local prefix=$1
	local outvar=$2
	for i in $(seq 60); do
		echo -n "${bold}Checking ${prefix} pod status... ${norm}"
		local getpods=$(kubectl -n spire get pods 2>/dev/null | grep ${prefix} || true)
		if [ -z "${getpods}" ]; then
			echo "${yellow}NotFound${norm}."
			sleep ${CHECKINTERVAL}
			continue
		fi
		local podname=$(echo ${getpods} | awk '{print $1}')
		local podstatus=$(echo ${getpods} | awk '{print $3}')
		if [ "${podstatus}" != "Running" ]; then
			echo "${yellow}${podstatus}${norm}."
			sleep ${CHECKINTERVAL}
			continue
		fi
		echo "${green}Running (${podname})${norm}."
		# I'd rather use name binding, but macOS ships with Bash 3. Silly macOS.
		eval $outvar=\${podname}
		return
	done

	echo "${red}failed${norm}."
	echo "${red}FAILED: ${prefix} pod not running in time${norm}"
	exit -1
}

wait_for_server() {
	wait_for_pod spire-server SPIRE_SERVER_POD_NAME
}

wait_for_agent() {
	wait_for_pod spire-agent SPIRE_AGENT_POD_NAME
}

check_for_node_attestation() {
	# spin for 60 seconds, checking to see if the agent attests
	for i in $(seq 60); do
		sleep ${CHECKINTERVAL}
		echo -n "${bold}Checking for node attestation... ${norm}"
		kubectl -n spire logs ${SPIRE_SERVER_POD_NAME} > ${SERVERLOGS} || true
		if  grep -sxq -e ".*Node attestation request .* completed .* k8s_sat.*" ${SERVERLOGS}; then
			echo "${green}ok${norm}."
			return
		fi
		echo "${yellow}nope${norm}."
	done

	echo "${red}FAILED: node attestation did not succeed in time.${norm}" >&2
	echo "${yellow}Log at ${SERVERLOGS}${norm}" >&2
	exit -1
}

trap cleanup EXIT
start_minikube
make_containers
apply_server_config
wait_for_server
apply_agent_config
wait_for_agent
check_for_node_attestation

echo "${bold}Success.${norm}"
