#!/bin/sh

set -e -o pipefail

# Configure Root CA
vault secrets enable pki
vault secrets tune -max-lease-ttl=8760h pki
vault write pki/root/generate/internal \
      common_name="root-ca" \
      uri_sans="spiffe://root-ca" \
      exclude_cn_from_sans=true \
      ttl=8760h > /dev/null
vault write pki/config/urls \
      issuing_certificates="http://vault.vault.svc:8200/v1/pki/ca" \
     crl_distribution_points="http://vault.vault.svc:8200/v1/pki/crl"

# Configure Intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int
vault write --field=csr pki_int/intermediate/generate/internal \
      common_name="intermediate-ca-vault" \
      ttl=43800h > /tmp/pki_int.csr
vault write --field=certificate pki/root/sign-intermediate \
      csr=@/tmp/pki_int.csr \
      common_name="intermediate-ca-vault" \
      uri_sans="spiffe://intermediate-ca-vault" \
      exclude_cn_from_sans=true \
      format=pem_bundle \
      ttl=43800h > /tmp/signed_certificate.pem
vault write pki_int/intermediate/set-signed certificate=@/tmp/signed_certificate.pem > /dev/null
vault write pki_int/config/urls \
      issuing_certificates="http://vault.vault.svc:8200/v1/pki_int/ca" \
      crl_distribution_points="http://vault.vault.svc:8200/v1/pki_int/crl"
