package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/spiffe/spire/proto/spire/api/agent/debug/v1"
	debug_server "github.com/spiffe/spire/proto/spire/api/server/debug/v1"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	socketPathFlag = flag.String("debugSocketPath", "unix:///opt/debug.sock", "agent socket path")

	testCaseFlag = flag.String("testCase", "agentEndpoints", "running test case")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch *testCaseFlag {
	case "agentEndpoints":
		agentEndpoints(ctx)
	case "serverWithWorkload":
		serverWithWorkload(ctx)
	case "serverWithInsecure":
		serverWithInsecure(ctx)
	default:
		log.Fatal("Unsupported test case")
	}
}

func agentEndpoints(ctx context.Context) {
	conn, err := grpc.Dial(*socketPathFlag, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect server: %v", err)
	}
	defer conn.Close()

	client := debug.NewDebugClient(conn)
	resp, err := client.GetInfo(ctx, &debug.GetInfoRequest{})
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

func serverWithWorkload(ctx context.Context) {
	itClient := itclient.New(ctx)
	defer itClient.Release()

	debugClient := itClient.DebugClient()
	_, err := debugClient.GetInfo(ctx, &debug_server.GetInfoRequest{})
	validateError(err)
}

func serverWithInsecure(ctx context.Context) {
	itClient := itclient.NewInsecure(ctx)
	defer itClient.Release()

	debugClient := itClient.DebugClient()
	_, err := debugClient.GetInfo(ctx, &debug_server.GetInfoRequest{})
	validateError(err)
}

func validateError(err error) {
	switch status.Code(err) {
	case codes.OK:
		log.Fatalf("connection using TCP must fails")
	case codes.Unimplemented:
		log.Print("success!")
	default:
		log.Fatalf("unexpected error: %v", err)
	}
}
