package command

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"github.com/go-kit/kit/log/level"
	"github.com/go-kit/kit/log"


	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/agent/keymanager"
	"github.com/spiffe/sri/pkg/agent/nodeattestor"
	"github.com/spiffe/sri/pkg/agent/workloadattestor"
	"github.com/spiffe/sri/cmd/spire-agent/endpoints/server"
)

const (
	DefaultAgentConifigPath = ".conf/default_agent_config.hcl"
	DefaultPluginConfigDir  = "../../plugin/agent/.conf"
)

var (

	PluginTypeMap = map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"KeyManager":       1,
		"NodeAttestor":     1,
		"WorkloadAttestor": 1,
	}

	logger = log.NewLogfmtLogger(os.Stdout)
)

type ServerCommand struct {
}

func (*ServerCommand) Help() string {
	return "Usage: sri/node_agent server"
}

func (*ServerCommand) Run(args []string) int {
	saConfigPath, isPathSet := os.LookupEnv("SPIRE_AGENT_CONFIG_PATH")
	if !isPathSet {
		saConfigPath = DefaultAgentConifigPath
	}

	config := helpers.ControlPlaneConfig{}
	err := config.ParseConfig(saConfigPath)
	if err != nil {
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger.Log("error", err, "configFile", saConfigPath)
		return -1

	}
	logger, err = helpers.NewLogger(&config)
	if err != nil {
		logger.Log("error", err)
		return -1
	}
	pluginCatalog, err := loadPlugins()
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	err = initEndpoints(pluginCatalog)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	return 0

}

func (*ServerCommand) Synopsis() string {
	return "Intializes sri/node_agent Runtime."
}

func loadPlugins() (*helpers.PluginCatalog, error) {
	pluginConfigDir, isPathSet := os.LookupEnv("SPIRE_PLUGIN_CONFIG_DIR")
	if !isPathSet {
		pluginConfigDir = DefaultPluginConfigDir
	}
	pluginCatalog := &helpers.PluginCatalog{
		PluginConfDirectory: pluginConfigDir,
	}
	pluginCatalog.SetMaxPluginTypeMap(MaxPlugins)
	pluginCatalog.SetPluginTypeMap(PluginTypeMap)
	err := pluginCatalog.Run()
	if err != nil {
		return nil, err
		level.Error(logger).Log("error",err)
	}

	return pluginCatalog, nil
}

func initEndpoints(pluginCatalog *helpers.PluginCatalog) error {
	errChan := makeErrorChannel()
	svc := server.NewService(pluginCatalog, errChan)

	var (
		gRPCAddr = flag.String("grpc", ":8081", "gRPC listen address") //TODO: read this from the cli arguments @kunzimariano
	)
	flag.Parse()

	endpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(svc),
		StopEndpoint:       server.MakeStopEndpoint(svc),
	}

	go func() {
		listener, err := net.Listen("tcp", *gRPCAddr)
		if err != nil {
			errChan <- err
			return
		}
		level.Info(logger).Log("grpc",gRPCAddr)

		handler := server.MakeGRPCServer(endpoints)
		gRPCServer := grpc.NewServer()
		sriplugin.RegisterServerServer(gRPCServer, handler)
		errChan <- gRPCServer.Serve(listener)
	}()

	error := <-errChan
	return error
}

func makeErrorChannel() (errChannel chan error) {
	errChannel = make(chan error)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errChannel <- fmt.Errorf("%s", <-c)
	}()
	return
}
