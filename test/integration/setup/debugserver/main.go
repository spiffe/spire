package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	socketPathFlag = flag.String("socket", "unix:///tmp/spire-server/private/api.sock", "server socket path")
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Debug server client fails: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *socketPathFlag, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect server: %w", err)
	}
	defer conn.Close()

	client := debugv1.NewDebugClient(conn)
	resp, err := client.GetInfo(ctx, &debugv1.GetInfoRequest{})
	if err != nil {
		return fmt.Errorf("failed to get info: %w", err)
	}

	m := protojson.MarshalOptions{Indent: " "}
	s, err := m.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to parse proto: %w", err)
	}
	log.Printf("Debug info: %s", string(s))
	return nil
}
