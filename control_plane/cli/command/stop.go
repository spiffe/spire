package command

import (
	"log"

	pb "github.com/spiffe/sri/control_plane/api/server/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type StopCommand struct {
}

func (*StopCommand) Help() string {
	return "Usage: sri/control_plane stop"
}

func (*StopCommand) Run(args []string) int {
	const (
		address = "localhost:8081" //TODO: read this from the cli arguments @kunzimariano
	)

	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to: %v.", err)
		return -1
	}
	defer conn.Close()
	c := pb.NewServerClient(conn)

	_, err = c.Stop(context.Background(), &pb.StopRequest{})

	if err != nil {
		log.Fatalf("Error: %v", err)
		return -1
	}
	log.Printf("Stop message sent.")

	return 0
}

func (*StopCommand) Synopsis() string {
	return "Stops sri/control_plane server."
}
