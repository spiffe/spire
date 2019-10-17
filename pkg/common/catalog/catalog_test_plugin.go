// +build ignore

// This file is used during testing. It is built as an external binary and
// loaded as an external plugin.
package main

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/catalog/test"
)

func main() {
	catalog.PluginMain(catalog.MakePlugin("test",
		test.TestPluginPluginServer(test.NewTestPlugin()),
		test.TestServiceServiceServer(test.NewTestService()),
	))
}
