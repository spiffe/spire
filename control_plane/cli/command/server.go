package command

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	registration_proto "github.com/spiffe/sri/control_plane/api/registration/proto"
	server_proto "github.com/spiffe/sri/control_plane/api/server/proto"
	"github.com/spiffe/sri/control_plane/endpoints/registration"
	"github.com/spiffe/sri/control_plane/endpoints/server"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/services"
)

type ServerCommand struct {
}

//Help returns how to use the server command
func (*ServerCommand) Help() string {
	return "Usage: sri/control_plane server"
}

//Run the server command
func (*ServerCommand) Run(args []string) int {
	pluginCatalog, err := loadPlugins()
	if err != nil {
		log.Fatal(err)
		return -1
	}

	err = initEndpoints(pluginCatalog)
	if err != nil {
		return -1
	}

	return 0
}

//Synopsis of the server command
func (*ServerCommand) Synopsis() string {
	return "Intializes sri/control_plane Runtime."
}

func loadPlugins() (*pluginhelper.PluginCatalog, error) {
	pluginCatalog := &pluginhelper.PluginCatalog{
		PluginConfDirectory: os.Getenv("PLUGIN_CONFIG_PATH"),
	}
	err := pluginCatalog.Run()
	if err != nil {
		return nil, err
	}

	return pluginCatalog, nil
}

func initEndpoints(pluginCatalog *pluginhelper.PluginCatalog) error {
	//Shouldn't we get this by plugin type?
	dataStore := pluginCatalog.GetPlugin("datastore")
	dataStoreImpl := dataStore.(datastore.DataStore)
	registrationService := services.NewRegistrationImpl(dataStoreImpl)

	errChan := makeErrorChannel()
	serverSvc := server.NewService(pluginCatalog, errChan)
	registrationSvc := registration.NewService(registrationService)

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
		log.Println("grpc:", *gRPCAddr)

		serverHandler := server.MakeGRPCServer(serverEndpoints)
		registrationHandler := registration.MakeGRPCServer(registrationEndpoints)
		gRPCServer := grpc.NewServer()
		server_proto.RegisterServerServer(gRPCServer, serverHandler)
		registration_proto.RegisterRegistrationServer(gRPCServer, registrationHandler)
		errChan <- gRPCServer.Serve(listener)
	}()

	go func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		mux := runtime.NewServeMux()
		opts := []grpc.DialOption{grpc.WithInsecure()}
		log.Println("http:", *httpAddr)
		err := registration_proto.RegisterRegistrationHandlerFromEndpoint(ctx, mux, *gRPCAddr, opts)
		if err != nil {
			errChan <- err
			return
		}
		errChan <- http.ListenAndServe(*httpAddr, mux)
	}()

	error := <-errChan
	log.Fatalln(error)
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
