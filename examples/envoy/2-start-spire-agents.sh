#!/bin/bash

set -e

bb=$(tput bold)
nn=$(tput sgr0)

# Start up the web server SPIRE agent, first copying over the spire server bundle
# to bootstrap agent to server trust. Alternatively, an upstream CA could be
# configured on the SPIRE server.
echo "${bb}Starting web server SPIRE agent...${nn}"
docker-compose exec -T spire-server bin/spire-server bundle show |
	docker-compose exec -T web tee conf/agent/bootstrap.crt > /dev/null
docker-compose exec -d web bin/spire-agent run

# Start up the echo server SPIRE agent, first copying over the spire server bundle
# to bootstrap agent to server trust. Alternatively, an upstream CA could be
# configured on the SPIRE server.
echo "${bb}Starting echo server SPIRE agent...${nn}"
docker-compose exec -T spire-server bin/spire-server bundle show |
	docker-compose exec -T echo tee conf/agent/bootstrap.crt > /dev/null
docker-compose exec -d echo bin/spire-agent run
