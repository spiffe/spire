// +build tools

package tools

import (
	_ "github.com/AlekSi/gocoverutil"
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/jteeuwen/go-bindata/go-bindata"
	_ "github.com/mattn/goveralls"
)
