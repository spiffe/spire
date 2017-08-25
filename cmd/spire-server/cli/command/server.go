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

	"github.com/spiffe/sri/pkg/common/plugin"

	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/spiffe/sri/pkg/server/datastore"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
	"github.com/spiffe/sri/pkg/server/noderesolver"
	"github.com/spiffe/sri/pkg/server/upstreamca"

	pb "github.com/spiffe/sri/pkg/api/registration"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/registration"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/server"

	"github.com/hashicorp/go-plugin"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/services"
	"reflect"
)

const (
	DefaultCPConifigPath = ".conf/default_cp_config.hcl"
	DefaultPluginConfigDir = "plugins/.conf"
)


var (

	PluginTypeMap = map[string]plugin.Plugin{
		"ControlPlaneCA":   &ca.ControlPlaneCaPlugin{},
		"DataStore":        &datastore.DataStorePlugin{},
		"NodeResolver":     &noderesolver.NodeResolverPlugin{},
		"UpstreamCA":       &upstreamca.UpstreamCaPlugin{},
		"CPNodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"ControlPlaneCA":   1,
		"DataStore":        1,
		"NodeResolver":     1,
		"UpstreamCA":       1,
		"CPNodeAttestor":   1,

	}
	logger = log.NewLogfmtLogger(os.Stdout)

)

type ServerCommand struct {
}
//Help returns how to use the server command
func (*ServerCommand) Help() string {
	return "Usage: spire-server server"
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
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger.Log("error", err , "configFile", cpConfigPath)
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

	err = initEndpoints(pluginCatalog, &config)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	return 0
}

//Synopsis of the server command
func (*ServerCommand) Synopsis() string {
	return "Intializes spire-server Runtime."
}

func loadPlugins() (*helpers.PluginCatalog, error) {
	pluginConfigDir, isPathSet := os.LookupEnv("PLUGIN_CONFIG_PATH")
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

func initEndpoints(pluginCatalog *helpers.PluginCatalog, config *helpers.ControlPlaneConfig) error {
	//Shouldn't we get this by plugin type?

	dataStore := pluginCatalog.GetPlugin("datastore")
	level.Info(logger).Log("pluginType",reflect.TypeOf(dataStore))
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
		pb.RegisterRegistrationServer(gRPCServer, registrationHandler)
		errChan <- gRPCServer.Serve(listener)
	}()

	go func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		mux := runtime.NewServeMux()
		opts := []grpc.DialOption{grpc.WithInsecure()}
		logger.Log("http:", *httpAddr)
		err := pb.RegisterRegistrationHandlerFromEndpoint(ctx, mux, *gRPCAddr, opts)
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
