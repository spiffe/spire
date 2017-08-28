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

	"github.com/spiffe/sri/cmd/spire-server/endpoints/node"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/registration"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/server"
	nodePB "github.com/spiffe/sri/pkg/api/node"
	registrationPB "github.com/spiffe/sri/pkg/api/registration"

	"reflect"

	"reflect"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/services"
)

const (
	DefaultServerConfigPath = ".conf/default_server_config.hcl"
	DefaultPluginConfigDir  = "../../plugin/server/.conf"
)

var (
	PluginTypeMap = map[string]plugin.Plugin{
		"ControlPlaneCA": &ca.ControlPlaneCaPlugin{},
		"DataStore":      &datastore.DataStorePlugin{},
		"NodeResolver":   &noderesolver.NodeResolverPlugin{},
		"UpstreamCA":     &upstreamca.UpstreamCaPlugin{},
		"NodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"ControlPlaneCA": 1,
		"DataStore":      1,
		"NodeResolver":   1,
		"UpstreamCA":     1,
		"NodeAttestor":   1,
	}
	logger = log.NewLogfmtLogger(os.Stdout)
)

type StartCommand struct {
}

//Help returns how to use the server command
func (*StartCommand) Help() string {
	return "Usage: spire-server server"
}

//Run the server command
func (*StartCommand) Run(args []string) int {
	cpConfigPath, isPathSet := os.LookupEnv("SPIRE_SERVER_CONFIG")
	if !isPathSet {
		cpConfigPath = DefaultServerConfigPath
	}

	config := helpers.ControlPlaneConfig{}
	err := config.ParseConfig(cpConfigPath)
	if err != nil {
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger.Log("error", err, "configFile", cpConfigPath)
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

//Synopsis of the server command
func (*StartCommand) Synopsis() string {
	return "Intializes spire-server Runtime."
}

func loadPlugins() (*helpers.PluginCatalog, error) {
	pluginConfigDir, isPathSet := os.LookupEnv("SPIRE_PLUGIN_CONFIG_DIR")
	if !isPathSet {
		pluginConfigDir = DefaultPluginConfigDir
	}
	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "pluginLogger",
		Level: hclog.LevelFromString("DEBUG"),
	})

	pluginCatalog := &helpers.PluginCatalog{
		PluginConfDirectory: pluginConfigDir,
		Logger:              pluginLogger,
	}
	pluginCatalog.SetMaxPluginTypeMap(MaxPlugins)
	pluginCatalog.SetPluginTypeMap(PluginTypeMap)
	err := pluginCatalog.Run()
	if err != nil {
		level.Error(logger).Log("error", err)
		return nil, err
	}

	return pluginCatalog, nil
}

func initEndpoints(pluginCatalog *helpers.PluginCatalog) error {
	//Shouldn't we get plugins by type instead of name?
	//plugins
	nodeAttestor := pluginCatalog.GetPlugin("join_token")
	level.Info(logger).Log("pluginType", reflect.TypeOf(nodeAttestor))
	nodeAttestorImpl := nodeAttestor.(nodeattestor.NodeAttestor)

	nodeResolver := pluginCatalog.GetPlugin("noop")
	level.Info(logger).Log("pluginType", reflect.TypeOf(nodeResolver))
	nodeResolverImpl := nodeResolver.(noderesolver.NodeResolver)

	serverCA := pluginCatalog.GetPlugin("ca_memory")
	level.Info(logger).Log("pluginType", reflect.TypeOf(serverCA))
	serverCAImpl := serverCA.(ca.ControlPlaneCa)

	dataStore := pluginCatalog.GetPlugin("datastore")
	level.Info(logger).Log("pluginType", reflect.TypeOf(dataStore))
	dataStoreImpl := dataStore.(datastore.DataStore)

	//services
	registrationService := services.NewRegistrationImpl(dataStoreImpl)
	attestationService := services.NewAttestationImpl(dataStoreImpl, nodeAttestorImpl)
	identityService := services.NewIdentityImpl(dataStoreImpl, nodeResolverImpl)
	caService := services.NewCAImpl(serverCAImpl)

	errChan := makeErrorChannel()
	var serverSvc server.ServerService
	serverSvc = server.NewService(pluginCatalog, errChan)
	serverSvc = server.ServiceLoggingMiddleWare(logger)(serverSvc)

	var registrationSvc registration.RegistrationService
	registrationSvc = registration.NewService(registrationService)
	registrationSvc = registration.ServiceLoggingMiddleWare(logger)(registrationSvc)

	var nodeSvc node.NodeService
	nodeSvc = node.NewService(attestationService, identityService, caService)
	nodeSvc = node.SelectorServiceLoggingMiddleWare(logger)(nodeSvc)

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

	nodeEnpoints := node.Endpoints{
		FetchBaseSVIDEndpoint:        node.MakeFetchBaseSVIDEndpoint(nodeSvc),
		FetchCPBundleEndpoint:        node.MakeFetchCPBundleEndpoint(nodeSvc),
		FetchFederatedBundleEndpoint: node.MakeFetchFederatedBundleEndpoint(nodeSvc),
		FetchSVIDEndpoint:            node.MakeFetchSVIDEndpoint(nodeSvc),
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
		nodeHandler := node.MakeGRPCServer(nodeEnpoints)
		gRPCServer := grpc.NewServer()

		sriplugin.RegisterServerServer(gRPCServer, serverHandler)
		registrationPB.RegisterRegistrationServer(gRPCServer, registrationHandler)
		nodePB.RegisterNodeServer(gRPCServer, nodeHandler)
		errChan <- gRPCServer.Serve(listener)
	}()

	go func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		mux := runtime.NewServeMux()
		opts := []grpc.DialOption{grpc.WithInsecure()}
		logger.Log("http:", *httpAddr)
		err := registrationPB.RegisterRegistrationHandlerFromEndpoint(ctx, mux, *gRPCAddr, opts)
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
