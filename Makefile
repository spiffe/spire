.PHONY: all default image_build cmd build test clean install

default: install test

all: install test

image_build:
	docker build -t spiffe-sri:latest .

cmd:
	docker run -v $(shell pwd):/code -it spiffe-sri:latest /bin/bash

build:
	docker run -w /root/go/src/github.com/spiffe/sri -v $(shell pwd):/root/go/src/github.com/spiffe/sri -it spiffe-sri:latest go build $$(glide novendor)	

test:
	docker run -w /root/go/src/github.com/spiffe/sri -v $(shell pwd):/root/go/src/github.com/spiffe/sri -it spiffe-sri:latest go test -race $$(glide novendor)

clean: 
	go clean
	rm -Rf vendor/*

install: image_build
	docker run -w /root/go/src/github.com/spiffe/sri -v $(shell pwd):/root/go/src/github.com/spiffe/sri -it spiffe-sri:latest glide install
  