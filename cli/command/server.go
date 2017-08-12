package command

import (
	"os"

	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/control-plane/helpers"

	"github.com/spiffe/control-plane/plugins/control_plane_ca"
	"github.com/spiffe/control-plane/plugins/data_store"
	"github.com/spiffe/control-plane/plugins/node_attestor"
	"github.com/spiffe/control-plane/plugins/node_resolver"
	"github.com/spiffe/control-plane/plugins/upstream_ca"
)

type ServerCommand struct {
}

var CP_PLUGIN_TYPE_MAP = map[string]plugin.Plugin{
	"ControlPlaneCa": &controlplaneca.ControlPlaneCaPlugin{},
	"DataStore":      &datastore.DataStorePlugin{},
	"NodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
	"NodeResolution": &noderesolver.NodeResolutionPlugin{},
	"UpstreamCa":     &upstreamca.UpstreamCaPlugin{},
}

func (*ServerCommand) Help() string {
	return "Usage: control-plane server"
}

func (*ServerCommand) Run(args []string) int {

	pluginCatlog := helpers.PluginCatalog{
		PluginConfDirectory: os.Getenv("PLUGIN_CONFIG_PATH")}
	/*err := pluginCatlog.LoadConfig()
	if err != nil {
		return -1
	}
	pluginCatlog.InitClients()*/
	pluginCatlog.Run(CP_PLUGIN_TYPE_MAP)
	return 0
}

func (*ServerCommand) Synopsis() string {
	return "Intializes control-plane Runtime"
}
