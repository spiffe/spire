ifeq ($(SPIRE_DEV_HOST), docker)
	docker = docker run -v $(docker_volume) -it $(docker_image)
	container = container
else
	docker = 
	container = 
endif

binary_dirs := $(shell find cmd/* functional/tools/* -maxdepth 0 -type d)
docker_volume := $(shell echo $${PWD%/src/*}):/root/go
docker_image = spire-dev:latest
gopath := $(shell go env GOPATH)
gittag := $(shell git tag --points-at)
gitdirty := $(shell git status -s)
# don't provide the git tag if the git status is dirty.
ifneq ($(gitdirty),)
	gittag :=
endif
ldflags := '-X github.com/spiffe/spire/pkg/common/version.gittag=$(gittag)'

utils = github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger \
		github.com/jteeuwen/go-bindata/go-bindata

.PHONY: all utils container-push cmd build test race-test clean functional

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
	$(docker) /bin/sh -c "cd $@; go build -i -ldflags $(ldflags)"

artifact:
	$(docker) ./build.sh artifact

test:
	$(docker) go test -race -timeout 8m $$(glide novendor)

race-test:
	$(docker) go test -race $$(glide novendor)

integration:
	$(docker) script/e2e_test.sh

clean:
	$(docker) go clean $$(glide novendor)

distclean: clean
	rm -rf .cache
	rm -rf vendor

functional:
	$(MAKE) -C functional/ all

noop:
