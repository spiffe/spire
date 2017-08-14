1. Create api/gk.json
2. In api/ run: gk new service service_name
3. In api/service_name/ add the interface methods for your service
4. In api/ run: gk init service_name
5. In api/service_name/pb populate the protobuf definition
6. In root run: make protobuf
7. In api/ run: gk init grpc service_name
8. Move service.go endpoints.go grpc_handler.go to endpoints/service_name/ (rename package name if necessary)
9. In endpoints.go rename New() to NewEndpoint()
10. In service.go rename New() to NewService()
11. In endpoints.go and grpc_handler.go fix the package renamed in 8 if necessary
12. In grpc_handler.go replace Reply with Response where necessary