ifdef CI
SHELL := /bin/bash
export PATH := $(HOME)/golang/bin:$(HOME)/protobuf/bin:$(HOME)/go/bin:$(HOME)/glide/bin:$(PATH)
export GOROOT := $(HOME)/golang
export GOPATH := $(HOME)/go
endif

build: generate_pb
	glide install
	go build -o ./nodeagent ./node_agent/node_agent.go
	go build -o ./plugins/node_attestor_aws ./plugins/node_attestor/aws/aws.go
	go build -o ./plugins/node_attestor_gcp ./plugins/node_attestor/gcp/gcp.go
	go build -o ./plugins/key_manager_memory ./plugins/key_manager/memory/memory.go
	go build -o ./plugins/node_attestor_secret_file ./plugins/node_attestor/secret_file/secret_file.go
	go build -o ./plugins/workload_attestor_secret_file ./plugins/workload_attestor/secret_file/secret_file.go

generate_pb:
	protoc ./api/workload/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/key_manager/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_attestor/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/workload_attestor/proto/*.proto --go_out=plugins=grpc:.

test:
	go test -v ./...
