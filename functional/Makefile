WORKLOADS := 10
TIMEOUT := 20
TTL := 150
SERVER_LOG := functional/server.log
AGENT_LOG := functional/agent.log

all: clean build server agent test

build:
	docker-compose build runner
	docker-compose up -d runner

server:
	cd .. && touch $(SERVER_LOG)
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-server/spire-server run -logLevel DEBUG -logFile $(SERVER_LOG)'
	sleep 5

agent:
	cd .. && touch $(AGENT_LOG)
	$(eval TOKEN := $(shell docker-compose exec runner /spire/functional/tools/tokengenerator/tokengenerator))
	@echo Generated join token is $(TOKEN)
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-agent/spire-agent run -joinToken $(TOKEN) -logLevel DEBUG -logFile $(AGENT_LOG)'
	sleep 5

test:
	docker-compose exec runner bash -c 'cd /spire/functional && tools/stresstest/stresstest -token=$(TOKEN) -workloads $(WORKLOADS) -timeout $(TIMEOUT) -ttl $(TTL)'
	docker-compose down

clean:
	docker-compose down
