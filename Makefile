ifeq ($(SPIRE_DEV_HOST), docker)
	docker = docker run -v $(docker_volume_spire) -v $(docker_volume_gopath) -it $(docker_image)
	container = container
else
	docker =
	container =
endif

binary_dirs := $(shell find cmd/* functional/tools/* -maxdepth 0 -type d)
docker_volume_gopath := $(shell echo $${GOPATH}/pkg/mod):/root/go/pkg/mod # Links mod to preserve cache
docker_volume_spire := $(shell echo $${PWD}):/root/spire # Copies spire
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

.PHONY: all utils container-push cmd build test race-test clean functional vendor

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

vendor: Gopkg.toml Gopkg.lock
	$(docker) dep ensure -vendor-only

$(binary_dirs): noop
	$(docker) /bin/sh -c "cd $@; GO111MODULE=on go build -ldflags $(ldflags)"

artifact:
	$(docker) ./build.sh artifact

test:
	$(docker) go test -race -timeout 8m github.com/spiffe/spire/...

race-test:
	$(docker) go test -race github.com/spiffe/spire/...

integration:
	$(docker) script/e2e_test.sh

clean:
	$(docker) go clean github.com/spiffe/spire/...

distclean: clean
	rm -rf .cache
	rm -rf vendor

functional:
	$(MAKE) -C functional/ all

noop:
