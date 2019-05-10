#/bin/bash

set -e

bb=$(tput bold)
nn=$(tput sgr0)

fingerprint() {
	# calculate the SHA1 digest of the DER bytes of the certificate using the
	# "coreutils" output format (`-r`) to provide uniform output from
	# `openssl sha1` on macOS and linux.
	cat $1 | openssl x509 -outform DER | openssl sha1 -r | awk '{print $1}'
}

WEB_AGENT_FINGERPRINT=$(fingerprint docker/web/conf/agent.crt.pem)
ECHO_AGENT_FINGERPRINT=$(fingerprint docker/echo/conf/agent.crt.pem)

echo "${bb}Creating registration entry for the web server...${nn}"
docker-compose exec spire-server bin/spire-server entry create \
	-parentID spiffe://domain.test/spire/agent/x509pop/${WEB_AGENT_FINGERPRINT} \
	-spiffeID spiffe://domain.test/web-server \
	-selector unix:user:root

echo "${bb}Creating registration entry for the echo server...${nn}"
docker-compose exec spire-server bin/spire-server entry create \
	-parentID spiffe://domain.test/spire/agent/x509pop/${ECHO_AGENT_FINGERPRINT} \
	-spiffeID spiffe://domain.test/echo-server \
	-selector unix:user:root
