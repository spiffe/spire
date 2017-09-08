ifeq ($(SPIRE_DEV_HOST), docker)
	cmd_prefix = docker run -v $(volume) -it $(docker_image)
	build_target = image_build
else
	cmd_prefix = 
	build_target = 
endif

volume = $(shell pwd):/root/go/src/github.com/spiffe/spire
docker_image = spiffe-spire-dev:latest

.PHONY: all default image_build cmd build test clean install

default: install test

all: install test

image_build:
	mkdir -p .build_cache
	docker build -t $(docker_image) .

cmd:
	$(cmd_prefix) /bin/bash

build:
	$(cmd_prefix) go build -i $$(glide novendor)	

race-test:
	$(cmd_prefix) go test -race $$(glide novendor)

test:
	$(cmd_prefix) go test $$(glide novendor)

clean: 
	go clean
	rm -Rf .build_cache/*
	rm -Rf vendor/*

install: $(build_target)
	$(cmd_prefix) glide install