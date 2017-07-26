ifdef CI
SHELL := /bin/bash
export PATH := $(HOME)/golang/bin:$(HOME)/protobuf/bin:$(HOME)/go/bin:$(HOME)/glide/bin:$(PATH)
export GOROOT := $(HOME)/golang
export GOPATH := $(HOME)/go
endif

<<<<<<< HEAD
<<<<<<< HEAD
BUILD_DIRS = control_plane $(shell find plugins/*/* -maxdepth 1 -type d -not -name 'proto')
BINARIES = $(foreach d,$(BUILD_DIRS),$(d)/$(notdir $(d)))

PROTOBUF_SRC = $(shell find plugins api -name '*.proto')
PROTOBUF_GO = $(foreach p,$(PROTOBUF_SRC:.proto=),$(p).pb.go)

all: build

setup:
	./build_setup.sh

build: deps protobuf binaries

deps:
	glide --home .cache install

protobuf: $(PROTOBUF_GO)
$(PROTOBUF_GO): %.pb.go: %.proto
	protoc $(@:.pb.go=.proto) --go_out=plugins=grpc:.

binaries: $(BINARIES)
$(BINARIES): %: %.go
	go build -o $(@) $(@).go

# PATH=PATH is to get around a gmake issue
test:
	go test -v $(shell PATH=$(PATH); glide novendor)

clean:
	rm -f $(BINARIES) $(PROTOBUF_GO)

distclean: clean
	rm -rf .cache .build 

.PHONY: clean distclean build protobuf binaries setup deps
