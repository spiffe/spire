package cli

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/wlcli/cli/command"
	"github.com/spiffe/spire/proto/api/workload"
)

func Run(args []string) int {
	c := cli.NewCLI("spire-server", "0.0.1") //TODO expose version configuration
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"fetchsvid": func() (cli.Command, error) {
			wc, ctx, cancel, err := createGrpcClient()
			if err != nil {
				log.Println(err)
				return nil, err
			}
			return &command.FetchSvid{
				WorkloadClient:        wc,
				WorkloadClientContext: ctx,
				Cancel:                cancel,
			}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}

func createGrpcClient() (workloadClient workload.WorkloadClient, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx = context.Background()
	ctx, cancel = context.WithCancel(ctx)

	conn, err := grpc.Dial("8080", // TODO: command line option?
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))

	workloadClient = workload.NewWorkloadClient(conn)

	return
}
