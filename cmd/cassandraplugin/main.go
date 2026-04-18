package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra"
)

type Plugin struct {
	cassandra.Plugin
}

func main() {
	plugin := cassandra.NewPlugin()
	pluginmain.Serve(
		datastorev1.DataStorePluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
