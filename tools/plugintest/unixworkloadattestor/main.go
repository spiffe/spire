package main

import (
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/unix"
	"github.com/spiffe/spire/pkg/common/catalog"
)

func main() {
	catalog.PluginMain(unix.BuiltIn())
}
