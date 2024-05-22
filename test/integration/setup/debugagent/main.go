package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	agent_debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	server_debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	socketPathFlag = flag.String("debugSocketPath", "unix:///opt/debug.sock", "agent socket path")

	testCaseFlag = flag.String("testCase", "agentEndpoints", "running test case")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		log.Fatalf("Debug client failed: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch *testCaseFlag {
	case "printDebugPage":
		err = printDebugPage(ctx)
	case "agentEndpoints":
		err = agentEndpoints(ctx)
	case "serverWithWorkload":
		err = serverWithWorkload(ctx)
	case "serverWithInsecure":
		err = serverWithInsecure(ctx)
	default:
		err = errors.New("unsupported test case")
	}

	return err
}

func agentEndpoints(ctx context.Context) error {
	s, err := retrieveDebugPage(ctx)
	if err != nil {
		return err
	}
	log.Printf("Debug info: %s", s)
	return nil
}

// printDebugPage allows integration tests to easily parse debug page with jq
func printDebugPage(ctx context.Context) error {
	s, err := retrieveDebugPage(ctx)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func retrieveDebugPage(ctx context.Context) (string, error) {
	conn, err := grpc.NewClient(*socketPathFlag, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", fmt.Errorf("failed to connect server: %w", err)
	}
	defer conn.Close()

	client := agent_debugv1.NewDebugClient(conn)
	resp, err := client.GetInfo(ctx, &agent_debugv1.GetInfoRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to get info: %w", err)
	}

	m := protojson.MarshalOptions{Indent: " "}
	s, err := m.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("failed to parse proto: %w", err)
	}
	return string(s), nil
}

func serverWithWorkload(ctx context.Context) error {
	itClient := itclient.New(ctx)
	defer itClient.Release()

	debugClient := itClient.DebugClient()
	_, err := debugClient.GetInfo(ctx, &server_debugv1.GetInfoRequest{})
	return validateError(err)
}

func serverWithInsecure(ctx context.Context) error {
	itClient := itclient.NewInsecure()
	defer itClient.Release()

	debugClient := itClient.DebugClient()
	_, err := debugClient.GetInfo(ctx, &server_debugv1.GetInfoRequest{})
	return validateError(err)
}

func validateError(err error) error {
	switch status.Code(err) {
	case codes.OK:
		return errors.New("connection using TCP must fails")
	case codes.Unimplemented:
		log.Print("success!")
		return nil
	default:
		return fmt.Errorf("unexpected error: %w", err)
	}
}
