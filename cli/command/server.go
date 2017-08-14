package command

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/spiffe/control-plane/api/server/proto"

	"github.com/spiffe/control-plane/control_plane/endpoints/server"
	"github.com/spiffe/control-plane/helpers"
)

type ServerCommand struct {
}

func (*ServerCommand) Help() string {
	return "Usage: control-plane server"
}

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

func (*ServerCommand) Synopsis() string {
	return "Intializes control-plane Runtime."
}

func loadPlugins() (*pluginhelper.PluginCatalog, error) {
	pluginCatalog := &pluginhelper.PluginCatalog{
		PluginConfDirectory: os.Getenv("PLUGIN_CONFIG_PATH")}
	err := pluginCatalog.Run()
	if err != nil {
		return nil, err
	}

	return pluginCatalog, nil
}

func initEndpoints(pluginCatalog *pluginhelper.PluginCatalog) error {
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
		log.Println("grpc:", *gRPCAddr)

		handler := server.MakeGRPCServer(endpoints)
		gRPCServer := grpc.NewServer()
		proto.RegisterServerServer(gRPCServer, handler)
		errChan <- gRPCServer.Serve(listener)
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
