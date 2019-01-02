// +build tools

package utils

import (
	_ "github.com/AlekSi/gocoverutil"
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/grpc-ecosystem/grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger"
	_ "github.com/jteeuwen/go-bindata/go-bindata"
	_ "github.com/mattn/goveralls"
)
