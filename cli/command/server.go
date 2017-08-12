package command

import (
	"os"

	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/control-plane/helpers"
)

type ServerCommand struct {
}

var CP_PLUGIN_TYPE_MAP = map[string]plugin.Plugin{}

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
