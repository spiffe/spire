#!/bin/sh

set -e -o pipefail

# Create Policy
vault policy write spire /tmp/spire.hcl

# Configure Vault Auth Method
vault auth enable approle
vault write auth/approle/role/spire \
      secret_id_ttl=120m \
      token_ttl=1m \
      policies="spire"

# Configure K8s Auth Method
vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT_HTTPS
vault write auth/kubernetes/role/my-role \
      bound_service_account_names=spire-server \
      bound_service_account_namespaces=spire \
      token_ttl=1m \
      policies=spire

# Configure Cert Auth Method
vault auth enable cert
vault write auth/cert/certs/my-role \
      display_name=spire \
      token_ttl=1m \
      policies=spire \
      certificate=@/tmp/cert_auth_ca.pem
