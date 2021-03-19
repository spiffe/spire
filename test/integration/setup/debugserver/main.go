package main

import (
	"context"
	"flag"
	"log"
	"time"

	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	socketPathFlag = flag.String("socket", "unix:///tmp/spire-server/private/api.sock", "server socket path")
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *socketPathFlag, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect server: %v", err)
	}
	defer conn.Close()

	client := debugv1.NewDebugClient(conn)
	resp, err := client.GetInfo(ctx, &debugv1.GetInfoRequest{})
	if err != nil {
		log.Fatalf("Failed to get info: %v", err)
	}

	m := protojson.MarshalOptions{Indent: " "}
	s, err := m.Marshal(resp)
	if err != nil {
		log.Fatalf("Failed to parse proto: %v", err)
	}
	log.Printf("Debug info: %s", string(s))
}
