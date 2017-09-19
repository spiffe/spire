ifeq ($(SPIRE_DEV_HOST), docker)
	docker = docker run -v $(docker_volume) -it $(docker_image)
	container = container
else
	docker = 
	container = 
endif

binary_dirs := $(shell find cmd/* plugin/*/* -maxdepth 0 -type d)
docker_volume := $(shell echo $${PWD%/src/*}):/root/go
docker_image = spiffe-spire-dev:latest

.PHONY: all utils cmd build test race-test clean

build: $(binary_dirs)

all: $(container) vendor build test

container: Dockerfile
	docker build -t $(docker_image) --no-cache .

cmd:
	$(docker) /bin/bash

utils:
	$(docker) go get github.com/golang/protobuf/protoc-gen-go
	$(docker) go get github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	$(docker) go get github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger

vendor: glide.yaml glide.lock
	$(docker) glide --home .cache install

$(binary_dirs): noop
	$(docker) /bin/sh -c "cd $@; go build -i"

test:
	$(docker) go test $$(glide novendor)

race-test:
	$(docker) go test -race $$(glide novendor)

clean:
	$(docker) go clean $$(glide novendor)

distclean: clean
	rm -rf .cache
	rm -rf vendor

noop:
