package cassandra

import (
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	ds_cassandra "github.com/spiffe/spire/pkg/server/datastore/cassandra"
)

const pluginName = "cassandra"

// BuiltIn returns the Cassandra plugin as a built-in. 
func BuiltIn() catalog.BuiltIn {
	return builtin(ds_cassandra.NewPlugin())
}

func builtin(plugin *ds_cassandra.Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(
		pluginName,
		datastorev1.DataStorePluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
