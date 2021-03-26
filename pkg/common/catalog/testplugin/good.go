// +build ignore

package main

import (
	"flag"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire/pkg/common/catalog/testplugin"
)

func main() {
	registerConfigFlag := flag.Bool("registerConfig", false, "register the configuration service")
	flag.Parse()
	builtIn := testplugin.BuiltIn(*registerConfigFlag)
	pluginmain.Serve(
		builtIn.Plugin,
		builtIn.Services...,
	)
}
