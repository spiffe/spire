// +build ignore

// This file is used during testing. It is built as an external binary and
// loaded as an external plugin.
package main

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/catalog/test"
	"github.com/spiffe/spire/proto/private/test/catalogtest"
)

func main() {
	catalog.PluginMain(catalog.MakePlugin("test",
		catalogtest.PluginPluginServer(test.NewPlugin()),
		catalogtest.ServiceServiceServer(test.NewService()),
	))
}
