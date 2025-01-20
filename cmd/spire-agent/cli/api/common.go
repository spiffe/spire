package api

import (
	"context"
	"flag"
	"net"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/metadata"
)

const commandTimeout = 5 * time.Second

type workloadClient struct {
	workload.SpiffeWorkloadAPIClient
	timeout time.Duration
}

type workloadClientMaker func(ctx context.Context, addr net.Addr, timeout time.Duration) (*workloadClient, error)

// newClients is the default client maker
func newWorkloadClient(ctx context.Context, addr net.Addr, timeout time.Duration) (*workloadClient, error) {
	target, err := util.GetTargetName(addr)
	if err != nil {
		return nil, err
	}
	conn, err := util.NewGRPCClient(target)
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
	common.ConfigOS // os specific

	env          *cli.Env
	clientsMaker workloadClientMaker
	cmd          command

	timeout cli.DurationFlag
	flags   *flag.FlagSet
}

// adaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func adaptCommand(env *cli.Env, clientsMaker workloadClientMaker, cmd command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
		timeout:      cli.DurationFlag(commandTimeout),
	}

	fs := flag.NewFlagSet(cmd.name(), flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Var(&a.timeout, "timeout", "Time to wait for a response")

	a.AddOSFlags(fs)
	a.cmd.appendFlags(fs)
	a.flags = fs

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		_ = a.env.ErrPrintln(err)
		return 1
	}

	addr, err := a.GetAddr()
	if err != nil {
		_ = a.env.ErrPrintln(err)
		return 1
	}
	clients, err := a.clientsMaker(ctx, addr, time.Duration(a.timeout))
	if err != nil {
		_ = a.env.ErrPrintln(err)
		return 1
	}

	if err := a.cmd.run(ctx, a.env, clients); err != nil {
		_ = a.env.ErrPrintln(err)
		return 1
	}

	return 0
}

func (a *adapter) Help() string {
	_ = a.flags.Parse([]string{"-h"})
	return ""
}

func (a *adapter) Synopsis() string {
	return a.cmd.synopsis()
}
