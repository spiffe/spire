# Parameters
WORKLOADS := 50
TIMEOUT := 30
TTL := 120

# Convenience vars
SERVER_LOG := functional/server.log
AGENT_LOG := functional/agent.log
DOCKER_SPIRE := /go/src/github.com/spiffe/spire

all: clean build server agent test

build:
	docker-compose build runner
	docker-compose up -d runner
	docker-compose exec runner bash -c 'mkdir -p $(DOCKER_SPIRE)/.data && cp -R /spire-orig/* $(DOCKER_SPIRE)'
	docker-compose exec runner bash -c 'cd $(DOCKER_SPIRE) && ./build.sh setup && ./build.sh binaries'

server:
	cd .. && touch $(SERVER_LOG)
	docker-compose exec -d runner bash -c 'cd $(DOCKER_SPIRE) && cmd/spire-server/spire-server run -logLevel DEBUG -logFile /spire-orig/$(SERVER_LOG)'
	sleep 5

agent:
	cd .. && touch $(AGENT_LOG)
	$(eval TOKEN := $(shell docker-compose exec runner $(DOCKER_SPIRE)/functional/tools/tokengenerator/tokengenerator))
	@echo Generated join token is $(TOKEN)
	docker-compose exec runner bash -c 'cd $(DOCKER_SPIRE)/functional && tools/stresstest/stresstest createusers -token=$(TOKEN) -workloads $(WORKLOADS) -ttl $(TTL)'
	docker-compose exec -d runner bash -c 'cd $(DOCKER_SPIRE) && cmd/spire-agent/spire-agent run -joinToken $(TOKEN) -logLevel DEBUG -logFile /spire-orig/$(AGENT_LOG)'
	sleep 1

test:
	docker-compose exec runner bash -c 'cd $(DOCKER_SPIRE)/functional && tools/stresstest/stresstest run -token=$(TOKEN) -workloads $(WORKLOADS) -timeout $(TIMEOUT) -ttl $(TTL)'
	docker-compose exec runner bash -c 'cp $(DOCKER_SPIRE)/functional/*.log /spire-orig/functional/'
	docker-compose down

clean:
	docker-compose down
