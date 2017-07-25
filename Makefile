export PATH := .build/go/bin:.build/protobuf/bin:.build/bin:$(PATH)

build: generate_all_pb
	go build -o ./controlplane ./control_plane/control_plane.go
	go build -o ./plugins/control_plane_ca_memory ./plugins/control_plane_ca/memory/memory.go
	go build -o ./plugins/data_store_sqlite ./plugins/data_store/sqlite/sqlite.go
	go build -o ./plugins/node_attestor_secret_file ./plugins/node_attestor/secret_file/secret_file.go
	go build -o ./plugins/node_resolution_noop ./plugins/node_resolution/noop/noop.go
	go build -o ./plugins/upstream_ca_memory ./plugins/upstream_ca/memory/memory.go

generate_all_pb:
	protoc ./api/node/*.proto --go_out=plugins=grpc:.
	protoc ./api/registration/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/control_plane_ca/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/data_store/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_attestor/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_resolution/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/upstream_ca/proto/*.proto --go_out=plugins=grpc:.
