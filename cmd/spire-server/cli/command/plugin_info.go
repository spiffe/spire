package command

import (
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type PluginInfoCommand struct {
}

func (*PluginInfoCommand) Help() string {
	return "Usage: spire-server plugin-info"
}

func (*PluginInfoCommand) Run(args []string) int {
	const (
		address = "localhost:8081" //TODO: read this from the cli arguments @kunzimariano
	)
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to: %v", err)
		return -1
	}
	defer conn.Close()
	c := spi.NewServerClient(conn)

	r, err := c.PluginInfo(context.Background(), &spi.PluginInfoRequest{})

	if err != nil {
		log.Fatalf("error: %v", err)
		return -1
	}
	log.Printf("PluginClient information: %s", r)

	return 0
}

func (*PluginInfoCommand) Synopsis() string {
	return "Gets spire-server plugins information."
}
