#/bin/bash

set -e

bb=$(tput bold)
nn=$(tput sgr0)

echo "${bb}Creating registration entry for the web server...${nn}"
docker-compose exec spire-server bin/spire-server entry create \
	-parentID spiffe://domain.test/spire/agent/x509pop/2963802ba4938e8a10180b7782d29c58e7282423 \
	-spiffeID spiffe://domain.test/web-server \
	-selector unix:user:root

echo "${bb}Creating registration entry for the echo server...${nn}"
docker-compose exec spire-server bin/spire-server entry create \
	-parentID spiffe://domain.test/spire/agent/x509pop/98baf916dad9eaf3cbc3b4f7c725ba8113f84c8a \
	-spiffeID spiffe://domain.test/echo-server \
	-selector unix:user:root
