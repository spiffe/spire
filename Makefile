ifeq ($(SPIRE_DEV_HOST), docker)
	docker = docker run -v $(docker_volume) -it $(docker_image)
	container = container
else
	docker = 
	container = 
endif

binary_dirs := $(shell find cmd/* plugin/*/* -maxdepth 0 -type d)
docker_volume := $(shell echo $${PWD%/src/*}):/root/go
docker_image = spire-dev:latest
gopath := $(shell go env GOPATH)

utils = github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger \
		github.com/jteeuwen/go-bindata/go-bindata

.PHONY: all utils container-push cmd build test race-test clean

build: $(binary_dirs)

all: $(container) vendor build test

container: Dockerfile
	docker build -t $(docker_image) --no-cache .

container-push:
	docker tag $(docker_image) spiffe/$(docker_image)
	docker push spiffe/$(docker_image)

cmd:
	$(docker) /bin/bash

utils: $(utils)

$(utils): noop
	# some sources do not contain buildable go, hence || true
	$(docker) /bin/sh -c "cd vendor/$@; go get . || true"
	$(docker) mkdir -p $(gopath)/src/$@
	$(docker) cp -r vendor/$@/* $(gopath)/src/$@/

vendor: glide.yaml glide.lock
	$(docker) glide --home .cache install

$(binary_dirs): noop
	$(docker) /bin/sh -c "cd $@; go build -i"

test:
	$(docker) go test -race $$(glide novendor)

race-test:
	$(docker) go test -race $$(glide novendor)

clean:
	$(docker) go clean $$(glide novendor)

distclean: clean
	rm -rf .cache
	rm -rf vendor

noop:
