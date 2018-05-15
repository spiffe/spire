#!/usr/bin/env bash
#
# This script generates a new dummy CA certificate and key for use in the
# SPIRE development environment. Note that it will place the generated certificate
# and key in the configuration directory, replacing any existing dummy certificates.
#

openssl ecparam -name secp384r1 -genkey -noout -out dummy_upstream_ca.key
openssl req -new -x509 -key dummy_upstream_ca.key -out dummy_upstream_ca.crt -days 1825 -subj "/C=US/ST=/L=/O=SPIFFE/OU=/CN=/"  -config <(
cat <<-EOF
[req]
default_bits = 2048
default_md = sha512
distinguished_name = dn
[ dn ]
[alt_names]
URI.1 = spiffe://local
[v3_req]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectAltName = @alt_names
EOF
) -extensions 'v3_req'
cp dummy_upstream_ca.crt ../conf/server
mv dummy_upstream_ca.crt ../conf/agent/dummy_root_ca.crt
mv dummy_upstream_ca.key ../conf/server
