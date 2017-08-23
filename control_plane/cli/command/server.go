package command

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/spiffe/sri/common/plugin"

	"github.com/spiffe/sri/control_plane/plugins/control_plane_ca"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
	cpnodeattestor "github.com/spiffe/sri/control_plane/plugins/node_attestor"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca"

	registration_proto "github.com/spiffe/sri/control_plane/api/registration/proto"
	"github.com/spiffe/sri/control_plane/endpoints/registration"
	"github.com/spiffe/sri/control_plane/endpoints/server"

	"github.com/hashicorp/go-plugin"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/services"
)

const (
	DefaultCPConifigPath = ".conf/default_cp_config.hcl"
)


var (

	PluginTypeMap = map[string]plugin.Plugin{
		"ControlPlaneCA":   &controlplaneca.ControlPlaneCaPlugin{},
		"DataStore":        &datastore.DataStorePlugin{},
		"NodeResolver":     &noderesolver.NodeResolverPlugin{},
		"UpstreamCA":       &upstreamca.UpstreamCaPlugin{},
		"CPNodeAttestor":   &cpnodeattestor.NodeAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"ControlPlaneCA":   1,
		"DataStore":        1,
		"NodeResolver":     1,
		"UpstreamCA":       1,
		"CPNodeAttestor":   1,
	}
)

type ServerCommand struct {
}

//Help returns how to use the server command
func (*ServerCommand) Help() string {
	return "Usage: sri/control_plane server"
}

//Run the server command
func (*ServerCommand) Run(args []string) int {
	cpConfigPath, isPathSet := os.LookupEnv("CP_CONFIG_PATH")
	if !isPathSet {
		cpConfigPath = DefaultCPConifigPath
	}

	config := helpers.ControlPlaneConfig{}
	err := config.ParseConfig(cpConfigPath)
	if err != nil {
		logger := log.NewLogfmtLogger(os.Stdout)
		logger.Log("error", err , "configFile", cpConfigPath)
		return -1

	}
	logger, err := helpers.NewLogger(&config)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}
	pluginCatalog, err := loadPlugins()
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	err = initEndpoints(pluginCatalog, logger, &config)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	return 0
}

//Synopsis of the server command
func (*ServerCommand) Synopsis() string {
	return "Intializes sri/control_plane Runtime."
}

func loadPlugins() (*helpers.PluginCatalog, error) {
	pluginCatalog := &helpers.PluginCatalog{
		PluginConfDirectory: os.Getenv("PLUGIN_CONFIG_PATH"),
	}
	pluginCatalog.SetMaxPluginTypeMap(MaxPlugins)
	pluginCatalog.SetPluginTypeMap(PluginTypeMap)
	err := pluginCatalog.Run()
	if err != nil {
		return nil, err
	}

	return pluginCatalog, nil
}

func initEndpoints(pluginCatalog *helpers.PluginCatalog, logger log.Logger, config *helpers.ControlPlaneConfig) error {
	//Shouldn't we get this by plugin type?
	dataStore := pluginCatalog.GetPlugin("datastore")
	dataStoreImpl := dataStore.(datastore.DataStore)
	registrationService := services.NewRegistrationImpl(dataStoreImpl)

	errChan := makeErrorChannel()
	var serverSvc server.ServerService
	serverSvc = server.NewService(pluginCatalog, errChan)
	serverSvc = server.ServiceLoggingMiddleWare(logger)(serverSvc)

	var registrationSvc registration.RegistrationService
	registrationSvc = registration.NewService(registrationService)
	registrationSvc = registration.ServiceLoggingMiddleWare(logger)(registrationSvc)

	var (
		httpAddr = flag.String("http", ":8080", "http listen address")
		gRPCAddr = flag.String("grpc", ":8081", "gRPC listen address")
	)
	flag.Parse()

	serverEndpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(serverSvc),
		StopEndpoint:       server.MakeStopEndpoint(serverSvc),
	}

	registrationEndpoints := registration.Endpoints{
		CreateEntryEndpoint:           registration.MakeCreateEntryEndpoint(registrationSvc),
		DeleteEntryEndpoint:           registration.MakeDeleteEntryEndpoint(registrationSvc),
		FetchEntryEndpoint:            registration.MakeFetchEntryEndpoint(registrationSvc),
		UpdateEntryEndpoint:           registration.MakeUpdateEntryEndpoint(registrationSvc),
		ListByParentIDEndpoint:        registration.MakeListByParentIDEndpoint(registrationSvc),
		ListBySelectorEndpoint:        registration.MakeListBySelectorEndpoint(registrationSvc),
		ListBySpiffeIDEndpoint:        registration.MakeListBySpiffeIDEndpoint(registrationSvc),
		CreateFederatedBundleEndpoint: registration.MakeCreateFederatedBundleEndpoint(registrationSvc),
		ListFederatedBundlesEndpoint:  registration.MakeListFederatedBundlesEndpoint(registrationSvc),
		UpdateFederatedBundleEndpoint: registration.MakeUpdateFederatedBundleEndpoint(registrationSvc),
		DeleteFederatedBundleEndpoint: registration.MakeDeleteFederatedBundleEndpoint(registrationSvc),
	}

	go func() {
		listener, err := net.Listen("tcp", *gRPCAddr)
		if err != nil {
			errChan <- err
			return
		}
		logger.Log("grpc:", *gRPCAddr)

		serverHandler := server.MakeGRPCServer(serverEndpoints)
		registrationHandler := registration.MakeGRPCServer(registrationEndpoints)
		gRPCServer := grpc.NewServer()
		sriplugin.RegisterServerServer(gRPCServer, serverHandler)
		registration_proto.RegisterRegistrationServer(gRPCServer, registrationHandler)
		errChan <- gRPCServer.Serve(listener)
	}()

	go func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		mux := runtime.NewServeMux()
		opts := []grpc.DialOption{grpc.WithInsecure()}
		logger.Log("http:", *httpAddr)
		err := registration_proto.RegisterRegistrationHandlerFromEndpoint(ctx, mux, *gRPCAddr, opts)
		if err != nil {
			errChan <- err
			return
		}
		errChan <- http.ListenAndServe(*httpAddr, mux)
	}()

	error := <-errChan
	logger.Log("channel", errChan, "error", error)
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
