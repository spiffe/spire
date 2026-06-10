package util

import (
	"context"
	"flag"
	"fmt"

	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewGRPCClient(addr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
}

type AgentClient interface {
	Release()
	NewLoggerClient() loggerv1.LoggerClient
}

func NewAgentClient(addr string) (AgentClient, error) {
	conn, err := NewGRPCClient(addr)
	if err != nil {
		return nil, err
	}
	return &agentClient{conn: conn}, nil
}

type agentClient struct {
	conn *grpc.ClientConn
}

func (c *agentClient) Release() {
	c.conn.Close()
}

func (c *agentClient) NewLoggerClient() loggerv1.LoggerClient {
	return loggerv1.NewLoggerClient(c.conn)
}

// Command is a common interface for commands in this package. The adapter
// can adapt this interface to the Command interface from github.com/mitchellh/cli.
type Command interface {
	Name() string
	Synopsis() string
	AppendFlags(*flag.FlagSet)
	Run(context.Context, *common_cli.Env, AgentClient) error
}

type Adapter struct {
	env *common_cli.Env
	cmd Command

	flags *flag.FlagSet

	adapterOS // OS specific
}

// AdaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func AdaptCommand(env *common_cli.Env, cmd Command) *Adapter {
	a := &Adapter{
		cmd: cmd,
		env: env,
	}

	f := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	f.SetOutput(env.Stderr)
	a.addOSFlags(f)
	a.cmd.AppendFlags(f)
	a.flags = f

	return a
}

func (a *Adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		return 1
	}

	addr := a.getGRPCAddr()
	client, err := NewAgentClient(addr)
	if err != nil {
		fmt.Fprintln(a.env.Stderr, "Error: "+err.Error())
		return 1
	}
	defer client.Release()

	if err := a.cmd.Run(ctx, a.env, client); err != nil {
		fmt.Fprintln(a.env.Stderr, "Error: "+err.Error())
		return 1
	}

	return 0
}

func (a *Adapter) Help() string {
	return a.flags.Parse([]string{"-h"}).Error()
}

func (a *Adapter) Synopsis() string {
	return a.cmd.Synopsis()
}
