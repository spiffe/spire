generate_all_pb:
	protoc ./plugins/control_plane_ca/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/data_store/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_attestation/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/node_resolution/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/upstream_ca/proto/*.proto --go_out=plugins=grpc:.
	protoc ./plugins/data_store/proto/*.proto --go_out=plugins=grpc:.
