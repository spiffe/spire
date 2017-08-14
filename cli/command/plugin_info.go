package command

import (
	"log"

	pb "github.com/spiffe/node-agent/api/server/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type PluginInfoCommand struct {
}

func (*PluginInfoCommand) Help() string {
	return "Usage: node-agent plugin-info"
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
	c := pb.NewServerClient(conn)

	r, err := c.PluginInfo(context.Background(), &pb.PluginInfoRequest{})

	if err != nil {
		log.Fatalf("error: %v", err)
		return -1
	}
	log.Printf("Plugin information: %s", r)

	return 0
}

func (*PluginInfoCommand) Synopsis() string {
	return "Gets node-agent plugins information."
}
