#!/bin/bash

EJBCA_NAMESPACE=ejbca
EJBCA_IMAGE="keyfactor/ejbca-ce"
EJBCA_TAG="latest"

IMAGE_PULL_SECRET_NAME=""

EJBCA_SUPERADMIN_SECRET_NAME="superadmin-tls"
EJBCA_MANAGEMENTCA_SECRET_NAME="managementca"
EJBCA_SUBCA_SECRET_NAME="subca"

EJBCA_ROOT_CA_NAME="Root-CA"
EJBCA_SUB_CA_NAME="Sub-CA"

# Verify that required tools are installed
verifySupported() {
    HAS_HELM="$(type "../bin/helm" &>/dev/null && echo true || echo false)"
    HAS_KUBECTL="$(type "../bin/kubectl" &>/dev/null && echo true || echo false)"
    HAS_JQ="$(type "jq" &>/dev/null && echo true || echo false)"
    HAS_CURL="$(type "curl" &>/dev/null && echo true || echo false)"
    HAS_OPENSSL="$(type "openssl" &>/dev/null && echo true || echo false)"

    if [ "${HAS_JQ}" != "true" ]; then
        echo "jq is required"
        exit 1
    fi

    if [ "${HAS_CURL}" != "true" ]; then
        echo "curl is required"
        exit 1
    fi

    if [ "${HAS_HELM}" != "true" ]; then
        echo "helm is required"
        exit 1
    fi

    if [ "${HAS_KUBECTL}" != "true" ]; then
        echo "kubectl is required"
        exit 1
    fi

    if [ "${HAS_OPENSSL}" != "true" ]; then
        echo "openssl is required"
        exit 1
    fi
}

###############################################
# EJBCA CA Creation and Initialization        #
###############################################

createConfigmapFromFile() { 
    local cluster_namespace=$1
    local configmap_name=$2
    local filepath=$3

    if [ $(../bin/kubectl get configmap -n "$cluster_namespace" -o json | jq -c ".items | any(.[] | .metadata; .name == \"$configmap_name\")") == "false" ]; then
        echo "Creating "$configmap_name" configmap"
        ../bin/kubectl create configmap -n "$cluster_namespace" "$configmap_name" --from-file="$filepath"
    else
        echo "$configmap_name exists"
    fi
}

# Figure out if the cluster is already initialized for EJBCA
isEjbcaAlreadyDeployed() {
    deployed=false
    if [ ! "$(../bin/kubectl --namespace "$EJBCA_NAMESPACE" get pods -l app.kubernetes.io/name=ejbca -o json | jq '.items[] | select(.metadata.labels."app.kubernetes.io/name" == "ejbca") | .metadata.name' | tr -d '"')" != "" ]; then
        echo "EJBCA is not deployed - EJBCA pod is not present"
        return 1
    fi
    
    if [[ ! $(../bin/kubectl get secret --namespace "$EJBCA_NAMESPACE" -o json | jq --arg "name" "$EJBCA_SUPERADMIN_SECRET_NAME" -e '.items[] | select(.metadata.name == $name)') ]]; then
        echo "EJBCA is not deployed - SuperAdmin secret is not present"
        return 1
    fi

    if [[ ! $(../bin/kubectl get secret --namespace "$EJBCA_NAMESPACE" -o json | jq --arg "name" "$EJBCA_SUPERADMIN_SECRET_NAME" -e '.items[] | select(.metadata.name == $name)') ]]; then
        echo "EJBCA is not deployed - ManagementCA secret is not present"
        return 1
    fi

    if [[ ! $(../bin/kubectl get secret --namespace "$EJBCA_NAMESPACE" -o json | jq --arg "name" "$EJBCA_SUPERADMIN_SECRET_NAME" -e '.items[] | select(.metadata.name == $name)') ]]; then
        echo "EJBCA is not deployed - SubCA secret is not present"
        return 1
    fi

    return 0
}

certificate_exists() {
    if [[ $(../bin/kubectl get certificate -o json | jq -r '.items.[] | select(.metadata.name == "ejbca-certificate")') == "" ]]; then
        return 1
    else
        return 0
    fi
}

# Waits for the EJBCA node to be ready
# cluster_namespace - The namespace where the EJBCA node is running
# ejbca_pod_name - The name of the Pod running the EJBCA node
waitForEJBCANode() {
    local cluster_namespace=$1
    local ejbca_pod_name=$2

    echo "Waiting for EJBCA node to be ready"
    until ! ../bin/kubectl -n "$cluster_namespace" exec "$ejbca_pod_name" -- /opt/keyfactor/bin/ejbca.sh 2>&1 | grep -q "could not contact EJBCA"; do
        echo "EJBCA node not ready yet, retrying in 5 seconds..."
        sleep 5
    done
    echo "EJBCA node $cluster_namespace/$ejbca_pod_name is ready."
}

configmapNameFromFilename() {
    local filename=$1
    echo "$(basename "$filename" | tr _ - | tr '[:upper:]' '[:lower:]')"
}

# Initialize the cluster for EJBCA
initClusterForEJBCA() {
    # Create the EJBCA namespace if it doesn't already exist
    if [ "$(../bin/kubectl get namespace -o json | jq -e '.items[] | select(.metadata.name == "'"$EJBCA_NAMESPACE"'") | .metadata.name')" == "" ]; then
        ../bin/kubectl create namespace "$EJBCA_NAMESPACE"
    fi

    # Mount the staged EEPs & CPs to Kubernetes with ConfigMaps
    for file in $(find ./ejbca/staging -maxdepth 1 -mindepth 1); do
        configmapname="$(basename "$file")"
        createConfigmapFromFile "$EJBCA_NAMESPACE" "$(configmapNameFromFilename "$configmapname")" "$file"
    done

    # Mount the ejbca init script to Kubernetes using a ConigMap
    createConfigmapFromFile "$EJBCA_NAMESPACE" "ejbca-init" "./ejbca/scripts/ejbca-init.sh"
}

# Clean up the config maps used to init the EJBCA database
cleanupEJBCAConfigMaps() {
    for file in $(find ./ejbca/staging -maxdepth 1 -mindepth 1); do
        configMapName="$(configmapNameFromFilename "$file")"
        ../bin/kubectl delete configmap --namespace "$EJBCA_NAMESPACE" "$configMapName"
    done
}

# Initialze the database by spinning up an instance of EJBCA infront of a MariaDB database, and
# create the CA hierarchy and import boilerplate profiles.
initEJBCADatabase() {
    helm_install_args=(
        "--namespace" 
        "$EJBCA_NAMESPACE" 
        "install" 
        "ejbca-test" 
        "./ejbca" 
        "--set" "ejbca.ingress.enabled=false"
    )

    container_staging_dir="/opt/keyfactor/stage"
    index=0
    for file in $(find ./ejbca/staging -maxdepth 1 -mindepth 1); do
        configMapName="$(configmapNameFromFilename "$file")"
        volume_name="$(echo "$configMapName" | sed 's/\.[^.]*$//')"

        helm_install_args+=("--set" "ejbca.volumes[$index].name=$volume_name")
        helm_install_args+=("--set" "ejbca.volumes[$index].configMapName=$configMapName")
        helm_install_args+=("--set" "ejbca.volumes[$index].mountPath=$container_staging_dir/$configMapName")
        index=$((index + 1))
    done

    helm_install_args+=("--set" "ejbca.volumes[$index].name=ejbca-init")
    helm_install_args+=("--set" "ejbca.volumes[$index].configMapName=ejbca-init")
    helm_install_args+=("--set" "ejbca.volumes[$index].mountPath=/tmp/")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[0].name=EJBCA_SUPERADMIN_COMMONNAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[0].value=SuperAdmin")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[1].name=EJBCA_SUPERADMIN_SECRET_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[1].value=$EJBCA_SUPERADMIN_SECRET_NAME")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[2].name=EJBCA_MANAGEMENTCA_SECRET_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[2].value=$EJBCA_MANAGEMENTCA_SECRET_NAME")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[2].name=EJBCA_SUBCA_SECRET_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[2].value=$EJBCA_SUBCA_SECRET_NAME")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[3].name=EJBCA_ROOT_CA_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[3].value=$EJBCA_ROOT_CA_NAME")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[4].name=EJBCA_SUB_CA_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[4].value=$EJBCA_SUB_CA_NAME")

    k8s_reverseproxy_service_fqdn="ejbca-rp-service.$EJBCA_NAMESPACE.svc.cluster.local"
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[5].name=EJBCA_CLUSTER_REVERSEPROXY_FQDN")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[5].value=$k8s_reverseproxy_service_fqdn")

    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[6].name=EJBCA_RP_TLS_SECRET_NAME")
    helm_install_args+=("--set" "ejbca.extraEnvironmentVars[6].value=ejbca-reverseproxy-tls")

    helm_install_args+=("--set" "ejbca.image.repository=$EJBCA_IMAGE")
    helm_install_args+=("--set" "ejbca.image.tag=$EJBCA_TAG")
    if [ ! -z "$IMAGE_PULL_SECRET_NAME" ]; then
        helm_install_args+=("--set" "ejbca.image.pullSecrets[0].name=$IMAGE_PULL_SECRET_NAME")
    fi

    if ! ../bin/helm "${helm_install_args[@]}" ; then
        echo "Failed to install EJBCA"
        ../bin/kubectl delete namespace "$EJBCA_NAMESPACE"
        exit 1
    fi

    # Wait for the EJBCA Pod to be ready
    echo "Waiting for EJBCA Pod to be ready"
    ../bin/kubectl --namespace "$EJBCA_NAMESPACE" wait --for=condition=Available deployment -l app.kubernetes.io/name=ejbca --timeout=300s
    ../bin/kubectl --namespace "$EJBCA_NAMESPACE" wait --for=condition=Ready pod -l app.kubernetes.io/name=ejbca --timeout=300s

    # Get the name of the EJBCA Pod
    local ejbca_pod_name
    ejbca_pod_name=$(../bin/kubectl --namespace "$EJBCA_NAMESPACE" get pods -l app.kubernetes.io/name=ejbca -o json | jq '.items[] | select(.metadata.labels."app.kubernetes.io/name" == "ejbca") | .metadata.name' | tr -d '"')

    if [ "$ejbca_pod_name" == "" ]; then
        echo "Failed to get the name of the EJBCA Pod"
        ../bin/kubectl delete ns "$EJBCA_NAMESPACE"
        exit 1
    fi

    # Wait for the EJBCA Pod to be ready
    waitForEJBCANode "$EJBCA_NAMESPACE" "$ejbca_pod_name"

    # Execute the EJBCA init script
    args=(
        --namespace "$EJBCA_NAMESPACE" exec "$ejbca_pod_name" --
        bash -c 'cp /tmp/ejbca-init.sh /opt/keyfactor/bin/ejbca-init.sh && chmod +x /opt/keyfactor/bin/ejbca-init.sh && /opt/keyfactor/bin/ejbca-init.sh'
    )
    if ! ../bin/kubectl "${args[@]}" ; then
        echo "Failed to execute the EJBCA init script"
        ../bin/kubectl delete ns "$EJBCA_NAMESPACE"
        exit 1
    fi

    # Uninstall the EJBCA helm chart - database is peristent
    ../bin/helm --namespace "$EJBCA_NAMESPACE" uninstall ejbca-test
    cleanupEJBCAConfigMaps
}

# Deploy EJBCA with ingress enabled
deployEJBCA() {
    # Package and deploy the EJBCA helm chart with ingress enabled
    helm_install_args=(
        "--namespace" 
        "$EJBCA_NAMESPACE" 
        "install" 
        "ejbca-test" 
        "./ejbca" 
        "--set" 
        "ejbca.ingress.enabled=false"
    )
    helm_install_args+=("--set" "ejbca.reverseProxy.enabled=true")

    helm_install_args+=("--set" "ejbca.image.repository=$EJBCA_IMAGE")
    helm_install_args+=("--set" "ejbca.image.tag=$EJBCA_TAG")
    if [ ! -z "$IMAGE_PULL_SECRET_NAME" ]; then
        helm_install_args+=("--set" "ejbca.image.pullSecrets[0].name=$IMAGE_PULL_SECRET_NAME")
    fi

    if ! ../bin/helm "${helm_install_args[@]}" ; then
        echo "Failed to install EJBCA"
        exit 1
    fi

    sleep 20
    
    # Wait for the EJBCA Pod to be ready
    echo "Waiting for EJBCA Pod to be ready"
    ../bin/kubectl --namespace "$EJBCA_NAMESPACE" wait --for=condition=ready pod -l app.kubernetes.io/instance=ejbca-test --timeout=300s

    # Get the name of the EJBCA Pod
    local ejbca_pod_name
    ejbca_pod_name=$(../bin/kubectl --namespace "$EJBCA_NAMESPACE" get pods -l app.kubernetes.io/name=ejbca -o json | jq '.items[] | select(.metadata.labels."app.kubernetes.io/name" == "ejbca") | .metadata.name' | tr -d '"')

    # Wait for the EJBCA node to be ready
    waitForEJBCANode "$EJBCA_NAMESPACE" "$ejbca_pod_name"

    sleep 5
}

uninstallEJBCA() {
    if ! isEjbcaAlreadyDeployed; then
        echo "EJBCA is not deployed"
        return 1
    fi

    ../bin/helm --namespace "$EJBCA_NAMESPACE" uninstall ejbca-test

    ../bin/kubectl delete namespace "$EJBCA_NAMESPACE"
}

###############################################
# Helper Functions                            #
###############################################

mariadbPvcExists() {
    local namespace=$1

    if [ "$(../bin/kubectl --namespace "$namespace" get pvc -l app.kubernetes.io/name=mariadb -o json | jq '.items[] | select(.metadata.labels."app.kubernetes.io/name" == "mariadb") | .metadata.name' | tr -d '"')" != "" ]; then
        return 0
    else
        return 1
    fi
}

usage() {
    echo "Usage: $0 [options...]"
    echo "Options:"
    echo "  --ejbca-image <image>               Set the image to use for the EJBCA node. Defaults to keyfactor/ejbca-ce"
    echo "  --ejbca-tag <tag>                   Set the tag to use for the EJBCA node. Defaults to latest"
    echo "  --image-pull-secret <secret>        Use a particular image pull secret in the ejbca namespace for the EJBCA node. Defaults to none"
    echo "  --ejbca-namespace <namespace>       Set the namespace to deploy the EJBCA node in. Defaults to ejbca"
    echo "  --superadmin-secret-name <secret>   The name of the secret that will be created containing the SuperAdmin (client certificate)"
    echo "  --managementca-secret-name <secret> The name of the secret that will be created containing the ManagementCA certificate"
    echo "  --subca-secret-name <secret>        The name of the secret that will be created containing the SubCA certificate and chain"
    echo "  --uninstall                         Uninstall EJBCA and SignServer"
    echo "  -h, --help                          Show this help message"
    exit 1
}

# Verify that required tools are installed
verifySupported

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ejbca-namespace)
            EJBCA_NAMESPACE="$2"
            shift # past argument
            shift # past value
            ;;
        --ejbca-image)
            EJBCA_IMAGE="$2"
            shift # past argument
            shift # past value
            ;;
        --superadmin-secret-name)
            EJBCA_SUPERADMIN_SECRET_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --managementca-secret-name)
            EJBCA_MANAGEMENTCA_SECRET_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --subca-secret-name)
            EJBCA_SUBCA_SECRET_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --ejbca-tag)
            EJBCA_TAG="$2"
            shift # past argument
            shift # past value
            ;;
        --image-pull-secret)
            IMAGE_PULL_SECRET_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --uninstall)
            uninstallEJBCA
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)    # unknown option
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Figure out if the cluster is already initialized for EJBCA
if ! isEjbcaAlreadyDeployed; then
    if mariadbPvcExists "$EJBCA_NAMESPACE"; then
        echo "The EJBCA database has already been configured - skipping database initialization"

        # Deploy EJBCA with ingress enabled
        deployEJBCA
    else
        # Prepare the cluster for EJBCA
        initClusterForEJBCA

        # Initialize the database by spinning up an instance of EJBCA infront of a MariaDB database, and then
        # create the CA hierarchy and import boilerplate profiles.
        initEJBCADatabase

        # Deploy EJBCA with ingress enabled
        deployEJBCA
    fi
fi
