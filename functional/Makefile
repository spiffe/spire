all: build server agent

build:
	docker-compose build runner
	docker-compose up -d runner

server:
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-server/spire-server run'
	sleep 5

agent:
	$(eval TOKEN := $(shell docker-compose exec runner bash -c 'cd /spire && cmd/spire-server/spire-server token generate'))
	@echo Generated join token is $(TOKEN)
	sleep 5
	docker-compose exec -d runner bash -c 'cd /spire && cmd/spire-agent/spire-agent run -joinToken $(TOKEN)'
	sleep 5

clean:
	docker-compose down
