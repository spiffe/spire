package main

import (
	"context"
	"flag"
	"net"
	"os"
	"time"

	workload "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"google.golang.org/grpc"
)

const (
	agentAddress = "/tmp/agent.sock"
)

func main() {
	ctx := context.Background()

	timeout := flag.Int("timeout", 0, "Total number of seconds that workload will run")
	flag.Parse()

	if *timeout == 0 {
		flag.Usage()
		return
	}

	log("Workload is up with uid %d! Will run for %d seconds\n\n", os.Getuid(), *timeout)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workloadClient, err := createGrpcClient(ctx, agentAddress)
	if err != nil {
		panic(err)
	}

	wl := NewWorkload(ctx, workloadClient, *timeout)

	err = wl.RunDaemon(ctx)
	if err != nil {
		panic(err)
	}
}

func createGrpcClient(ctx context.Context, agentAddr string) (workloadClient workload.SpiffeWorkloadAPIClient, err error) {
	conn, err := grpc.Dial(agentAddr,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", addr)
		}))
	if err != nil {
		return nil, err
	}

	return workload.NewSpiffeWorkloadAPIClient(conn), nil
}
