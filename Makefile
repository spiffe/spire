.PHONY: all build launch

default: launch

all: build launch

build:
	docker build -t spiffe-sri:latest .

launch:
	docker run -v $(shell pwd):/code -it spiffe-sri:latest

