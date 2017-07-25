ifdef CI
SHELL := /bin/bash
export PATH := .build/go/bin:.build/protobuf/bin:.build/bin:$(PATH)
export GOROOT := $(PWD)/.build/go
export GOPATH := $(PWD)/.build
endif

build: generate_all_pb
	go build -o ./nodeagent ./node_agent/node_agent.go
	go build -o ./plugins/key_manager_memory ./plugins/key_manager/memory/memory.go
	go build -o ./plugins/node_attestor_secret_file ./plugins/node_attestor/secret_file/secret_file.go
	go build -o ./plugins/workload_attestor_secret_file ./plugins/workload_attestor/secret_file/secret_file.go

generate_all_pb:
	protoc ./api/workload/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/key_manager/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_attestor/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/workload_attestor/proto/*.proto --go_out=plugins=grpc:.
