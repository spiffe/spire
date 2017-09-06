.PHONY: all build launch

default: launch

all: build launch

build:
	docker build -t spiffe-spire:latest .

launch:
	docker run -v $(shell pwd):/code -it spiffe-spire:latest

test:
	go test -race $$(glide novendor)
