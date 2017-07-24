export PATH := .build/go/bin:.build/protobuf/bin:.build/bin:$(PATH)

generate_all_pb:
	protoc ./api/workload/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/key_manager/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_attestor/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/workload_attestor/proto/*.proto --go_out=plugins=grpc:.
