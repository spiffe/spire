#!/bin/bash

###########
# General #
###########

ejbcactl() {
    local args=("${@:1}")

    echo "ejbca.sh ${args[*]}"

    if ! /opt/keyfactor/bin/ejbca.sh "${args[@]}" ; then
        echo "ejbca.sh failed with args: ${args[*]}"
        exit 1
    fi

    return 0
}


##############
# Kubernetes #
##############

createK8sTLSSecret() {
    local secret_name=$1
    local cert_file=$2
    local key_file=$3

    namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
    secret_url="https://$KUBERNETES_PORT_443_TCP_ADDR:$KUBERNETES_SERVICE_PORT_HTTPS/api/v1/namespaces/$namespace/secrets"
    ca_cert_path="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

    cert=$(cat $cert_file | base64 | tr -d '\n')
    key=$(cat $key_file | base64 | tr -d '\n')

    read -r -d '' PAYLOAD <<EOF
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "$secret_name",
            "namespace": "$namespace"
        },
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": "$cert",
            "tls.key": "$key"
        }
    }
EOF

    echo "Creating TLS secret $secret_name"

    # Send the request to create the secret
    curl -X POST \
        "$secret_url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        --cacert "$ca_cert_path" \
        -d "$PAYLOAD"
}

createK8sOpaqueSecret() {
    local secret_name=$1
    local key=$2
    local value=$3

    namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
    secret_url="https://$KUBERNETES_PORT_443_TCP_ADDR:$KUBERNETES_SERVICE_PORT_HTTPS/api/v1/namespaces/$namespace/secrets"
    ca_cert_path="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

    read -r -d '' PAYLOAD <<EOF
    {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "$secret_name",
            "namespace": "$namespace"
        },
        "type": "Opaque",
        "data": {
            "$key": "$value"
        }
    }
EOF

    echo "Creating TLS secret $secret_name"

    # Send the request to create the secret
    curl -X POST \
        "$secret_url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        --cacert "$ca_cert_path" \
        -d "$PAYLOAD"
}

#######################################
# Management, Root, & Sub CA creation #
#######################################

# Uses the EJBCA CLI inside a given EJBCA node to
# create a crypto token according to provided arguments
# name - The name of the crypto token
# type - The type of the crypto token (e.g. SoftCryptoToken)
# pin - The pin for the crypto token
# autoactivate - Whether or not to autoactivate the crypto token
createCryptoToken() {
    local name=$1
    local type=$2
    local pin=$3
    local autoactivate=$4

    echo "Creating crypto token $name"

    args=(
        cryptotoken
        create
        --token "$name"
        --type "$type"
        --pin "$pin"
        --autoactivate "$autoactivate")

    ejbcactl "${args[@]}"
}

# Uses the EJBCA CLI inside a given EJBCA node to
# generate a key-pair for a given crypto token
# token - The name of the crypto token
# alias - The alias for the key-pair
# keyspec - The key size
generateCryptoTokenKeyPair() {
    local token=$1
    local alias=$2
    local keyspec=$3

    echo "Generating key-pair $alias for crypto token $token"

    args=(
        cryptotoken
        generatekey
        --token "$token"
        --alias "$alias"
        --keyspec "$keyspec")

    ejbcactl "${args[@]}"
}

# Create a root CA
# name - The name of the CA to create. Will be used as CN too.
# token_prop_file - The path to the file containing the token properties
createRootCA() {
    local ca_name=$1
    local token_prop_file=$2

    echo "Initializing root CA called $ca_name"

    createCryptoToken "$ca_name" "SoftCryptoToken" 1234 true

    generateCryptoTokenKeyPair "$ca_name" "signKey" 2048
    generateCryptoTokenKeyPair "$ca_name" "encryptKey" 2048
    generateCryptoTokenKeyPair "$ca_name" "testKey" 2048

    args=(
        ca
        init
        --caname "$ca_name"
        --dn "CN=$ca_name,O=EJBCA"
        --keyspec 2048
        --keytype RSA
        --policy null
        -s SHA256WithRSA
        --tokenName "$ca_name"
        --tokenPass 1234
        --tokenprop "$token_prop_file"
        -v 3650)

    ejbcactl "${args[@]}"
}

# Creates a sub CA signed by a given CA
# ca_name - The name of the CA to create. Will be used as CN too.
# token_prop_file - The file containing the token properties
# signed_by - The name of the CA that will sign this CA
createSubCA() {
    local ca_name=$1
    local token_prop_file=$2
    local signed_by=$3

    echo "Creating intermediate CA called $ca_name"

    createCryptoToken "$ca_name" "SoftCryptoToken" 1234 true
    generateCryptoTokenKeyPair "$ca_name" "signKey" 2048
    generateCryptoTokenKeyPair "$ca_name" "encryptKey" 2048
    generateCryptoTokenKeyPair "$ca_name" "testKey" 2048

    local signed_by_id=$(ejbcactl ca info --caname "$signed_by" | grep " (main) CA ID: " | awk '{print $8}')

    args=(
        "ca"
        "init"
        "--caname" "$ca_name"
        "--signedby" "$signed_by_id"
        --dn "CN=$ca_name,O=EJBCA"
        --keyspec 2048
        --keytype RSA
        --policy null
        -s SHA256WithRSA
        --tokenName "$ca_name"
        --tokenPass 1234
        --tokenprop $token_prop_file
        -v 3650
    )

    ejbcactl "${args[@]}"
}

tokenProperties="/opt/keyfactor/token.properties"
touch $tokenProperties
echo "certSignKey signKey" > $tokenProperties
echo "crlSignKey signKey" >> $tokenProperties
echo "keyEncryptKey encryptKey" >> $tokenProperties
echo "testKey testKey" >> $tokenProperties
echo "defaultKey encryptKey" >> $tokenProperties

root_ca_name="$EJBCA_ROOT_CA_NAME"
if [ -z "$root_ca_name" ]; then
    echo "Using default root CA name Root-CA"
    root_ca_name="Root-CA"
fi
sub_ca_name="$EJBCA_SUB_CA_NAME"
if [ -z "$sub_ca_name" ]; then
    echo "Using default sub CA name Sub-CA"
    sub_ca_name="Sub-CA"
fi

createRootCA "ManagementCA" "$tokenProperties"
createRootCA "$root_ca_name" "$tokenProperties"
createSubCA "$sub_ca_name" "$tokenProperties" "$root_ca_name"

############################
# Import staged EEPs & CPs #
############################

container_staging_dir="$EJBCA_EEP_CP_STAGE_DIR"
if [ ! -s "$container_staging_dir" ]; then
    echo "Using default staging directory /opt/keyfactor/stage"
    container_staging_dir="/opt/keyfactor/stage"
fi

# Import end entity profiles from staging area
for file in "$container_staging_dir"/*; do
    echo "Importing profile from $file"
    ejbcactl ca importprofiles -d "$file"
done

##########################################
# Create SuperAdmin certificate and role #
##########################################

common_name="$EJBCA_SUPERADMIN_COMMONNAME"
if [ -z "$common_name" ]; then
    echo "Using default common name SuperAdmin"
    common_name="SuperAdmin"
fi

superadmin_secret_name="$EJBCA_SUPERADMIN_SECRET_NAME"
if [ -z "$superadmin_secret_name" ]; then
    echo "Using default secret name superadmin-tls"
    superadmin_secret_name="superadmin-tls"
fi

managementca_secret_name="$EJBCA_MANAGEMENTCA_SECRET_NAME"
if [ -z "$managementca_secret_name" ]; then
    echo "Using default secret name managementca"
    managementca_secret_name="managementca"
fi

# Create SuperAdmin
ejbcactl ra addendentity \
    --username "SuperAdmin" \
    --dn "CN=$common_name" \
    --caname "ManagementCA" \
    --certprofile "Authentication-2048-3y" \
    --eeprofile "adminInternal" \
    --type 1 \
    --token "PEM" \
    --password "foo123"

ejbcactl ra setclearpwd SuperAdmin foo123
ejbcactl batch

superadmin_cert="/opt/keyfactor/p12/pem/$common_name.pem"
superadmin_key="/opt/keyfactor/p12/pem/$common_name-Key.pem"
createK8sTLSSecret "$superadmin_secret_name" "$superadmin_cert" "$superadmin_key"
managementca_cert="/opt/keyfactor/p12/pem/$common_name-CA.pem"
createK8sOpaqueSecret "$managementca_secret_name" "ca.crt" "$(cat $managementca_cert | base64 | tr -d '\n')"

# Add a role to allow the SuperAdmin to access the node
ejbcactl roles addrolemember \
    --role 'Super Administrator Role' \
    --caname 'ManagementCA' \
    --with 'WITH_COMMONNAME' \
    --value "$common_name"

# Enable the /ejbca/ejbca-rest-api endpoint
ejbcactl config protocols enable --name "REST Certificate Management"

#########################################
# Create the in-cluster TLS certificate #
#########################################

subca_secret_name="$EJBCA_SUBCA_SECRET_NAME"
if [ -z "$managementca_secret_name" ]; then
    echo "Using default secret name subca"
    managementca_secret_name="subca"
fi

reverseproxy_fqdn="$EJBCA_CLUSTER_REVERSEPROXY_FQDN"
if [ -z "$reverseproxy_fqdn" ]; then
    echo "Skipping in-cluster reverse proxy TLS config - EJBCA_CLUSTER_REVERSEPROXY_FQDN not set"
    return 0
fi

reverseproxy_secret_name="$EJBCA_RP_TLS_SECRET_NAME"
if [ -z "$reverseproxy_secret_name" ]; then
    echo "Using default reverseproxy secret name ejbca-reverseproxy-tls"
    ingress_secret_name="ejbca-reverseproxy-tls"
fi

echo "Creating server certificate for $reverseproxy_fqdn"
ejbcactl ra addendentity \
    --username "$reverseproxy_fqdn" \
    --altname dNSName="$reverseproxy_fqdn" \
    --dn "CN=$reverseproxy_fqdn" \
    --caname "Sub-CA" \
    --certprofile "tlsServerAuth" \
    --eeprofile "tlsServerAnyCA" \
    --type 1 \
    --token "PEM" \
    --password "foo123"

ejbcactl ra setclearpwd "$reverseproxy_fqdn" foo123
ejbcactl batch

ls -l "/opt/keyfactor/p12/pem"

server_cert="/opt/keyfactor/p12/pem/$reverseproxy_fqdn.pem"
server_key="/opt/keyfactor/p12/pem/$reverseproxy_fqdn-Key.pem"
createK8sTLSSecret "$reverseproxy_secret_name" "$server_cert" "$server_key"
subca_cert="/opt/keyfactor/p12/pem/$reverseproxy_fqdn-CA.pem"
createK8sOpaqueSecret "$subca_secret_name" "ca.crt" "$(cat $subca_cert | base64 | tr -d '\n')"
