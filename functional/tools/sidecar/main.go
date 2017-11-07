package main

import (
	"context"
	"flag"
	"net"
	"os"
	"time"

	workload "github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc"
)

const (
	agentAddress = "/tmp/agent.sock"
)

func main() {
	timeout := flag.Int("timeout", 0, "Total number of seconds that sidecar will run")
	flag.Parse()

	if *timeout == 0 {
		flag.Usage()
		return
	}

	log("Sidecar is up with uid %d! Will run for %d seconds and use agent at %s\n\n", os.Getuid(), *timeout, agentAddress)

	workloadClient, ctx, cancel, err := createGrpcClient(agentAddress)
	defer cancel()
	if err != nil {
		panic(err)
	}

	sidecar := NewSidecar(ctx, workloadClient, *timeout)

	err = sidecar.RunDaemon()
	if err != nil {
		panic(err)
	}
}

func createGrpcClient(agentAddr string) (workloadClient workload.WorkloadClient, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx = context.Background()
	ctx, cancel = context.WithCancel(ctx)

	conn, err := grpc.Dial(agentAddr,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))

	workloadClient = workload.NewWorkloadClient(conn)

	return
}
