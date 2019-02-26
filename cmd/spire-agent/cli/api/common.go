package api

import (
	"context"
	"flag"
	"net"
	"time"

	workload_dial "github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc/metadata"
)

type workloadClient struct {
	workload.SpiffeWorkloadAPIClient
	timeout time.Duration
}

type workloadClientMaker func(ctx context.Context, socketPath string, timeout time.Duration) (*workloadClient, error)

// newClients is the default client maker
func newWorkloadClient(ctx context.Context, socketPath string, timeout time.Duration) (*workloadClient, error) {
	conn, err := workload_dial.Dial(ctx, &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		return nil, err
	}
	return &workloadClient{
		SpiffeWorkloadAPIClient: workload.NewSpiffeWorkloadAPIClient(conn),
		timeout:                 timeout,
	}, nil
}

func (c *workloadClient) prepareContext(ctx context.Context) (context.Context, func()) {
	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx = metadata.NewOutgoingContext(ctx, header)
	if c.timeout > 0 {
		return context.WithTimeout(ctx, c.timeout)
	}
	return ctx, func() {}
}

// command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type command interface {
	name() string
	synopsis() string
	appendFlags(*flag.FlagSet)
	run(context.Context, *cli.Env, *workloadClient) error
}

type adapter struct {
	env          *cli.Env
	clientsMaker workloadClientMaker
	cmd          command

	socketPath string
	timeout    cli.DurationFlag
	flags      *flag.FlagSet
}

// adaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func adaptCommand(env *cli.Env, clientsMaker workloadClientMaker, cmd command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
		timeout:      cli.DurationFlag(time.Second),
	}

	fs := flag.NewFlagSet(cmd.name(), flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.StringVar(&a.socketPath, "socketPath", common.DefaultSocketPath, "Path to Workload API socket")
	fs.Var(&a.timeout, "timeout", "Time to wait for a response")
	a.cmd.appendFlags(fs)
	a.flags = fs

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		a.env.ErrPrintln(err)
		return 1
	}

	clients, err := a.clientsMaker(ctx, a.socketPath, time.Duration(a.timeout))
	if err != nil {
		a.env.ErrPrintln(err)
		return 1
	}

	if err := a.cmd.run(ctx, a.env, clients); err != nil {
		a.env.ErrPrintln(err)
		return 1
	}

	return 0
}

func (a *adapter) Help() string {
	a.flags.Parse([]string{"-h"})
	return ""
}

func (a *adapter) Synopsis() string {
	return a.cmd.synopsis()
}
