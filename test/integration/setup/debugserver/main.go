package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/spiffe/spire/proto/spire/api/server/debug/v1"
	"google.golang.org/grpc"
)

var (
	socketPathFlag = flag.String("socket", "unix:///tmp/spire-registration.sock", "server socket path")
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *socketPathFlag, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect server: %v", err)
	}
	defer conn.Close()

	client := debug.NewDebugClient(conn)
	resp, err := client.GetInfo(ctx, &debug.GetInfoRequest{})
	if err != nil {
		log.Fatalf("Failed to get info: %v", err)
	}

	m := jsonpb.Marshaler{Indent: " "}
	s, err := m.MarshalToString(resp)
	if err != nil {
		log.Fatalf("Failed to parse proto: %v", err)
	}
	log.Printf("Debug info: %+v", s)
}
