WORKLOADS := 10
TIMEOUT := 20
TTL := 150

all: clean build server agent

build:
	docker-compose build runner
	docker-compose up -d runner

server:
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-server/spire-server run'
	sleep 5

agent:
	$(eval TOKEN := $(shell docker-compose exec runner /spire/functional/tools/tokengenerator/tokengenerator))
	@echo Generated join token is $(TOKEN)
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-agent/spire-agent run -joinToken $(TOKEN)'
	sleep 5
	docker-compose exec runner /spire/functional/tools/stresstest/stresstest -token=$(TOKEN) -workloads $(WORKLOADS) -timeout $(TIMEOUT) -ttl $(TTL)

clean:
	docker-compose down
