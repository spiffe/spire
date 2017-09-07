.PHONY: all default image_build cmd build test clean install

default: install test

all: install test

volume = $(shell pwd):/root/go/src/github.com/spiffe/spire
docker_image = spiffe-spire-dev:latest

image_build:
	docker build -t $(docker_image) .

cmd:
	docker run -v $(volume) -it $(docker_image) /bin/bash

build:
	docker run -v $(volume) -it $(docker_image) go build $$(glide novendor)	

test:
	docker run -v $(volume) -it $(docker_image) go test -race $$(glide novendor)

clean: 
	go clean
	rm -Rf vendor/*

install: image_build
	docker run -v $(volume) -it $(docker_image) glide install
  