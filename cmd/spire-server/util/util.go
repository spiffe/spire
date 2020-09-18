package util

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"google.golang.org/grpc"
)

const (
	DefaultSocketPath = "/tmp/spire-registration.sock"
)

func NewAgentClient(socketPath string) (agent.AgentClient, error) {
	conn, err := grpc.Dial(socketPath, grpc.WithInsecure(), grpc.WithDialer(dialer)) //nolint: staticcheck
	if err != nil {
		return nil, err
	}
	return agent.NewAgentClient(conn), err
}

func NewRegistrationClient(socketPath string) (registration.RegistrationClient, error) {
	conn, err := grpc.Dial(socketPath, grpc.WithInsecure(), grpc.WithDialer(dialer)) //nolint: staticcheck
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}

func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

// Pluralizer concatenates `singular` to `msg` when `val` is one, and
// `plural` on all other occasions. It is meant to facilitate friendlier
// CLI output.
func Pluralizer(msg string, singular string, plural string, val int) string {
	result := msg
	if val == 1 {
		result += singular
	} else {
		result += plural
	}

	return result
}

type Clients struct {
	AgentClient agent.AgentClient
}

type ClientsMaker func(registrationUDSPath string) (*Clients, error)

// NewClients is the default client maker
func NewClients(registrationUDSPath string) (*Clients, error) {
	agentClient, err := NewAgentClient(registrationUDSPath)
	if err != nil {
		return nil, err
	}

	return &Clients{
		AgentClient: agentClient,
	}, nil
}

// Command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type Command interface {
	Name() string
	Synopsis() string
	AppendFlags(*flag.FlagSet)
	Run(context.Context, *common_cli.Env, *Clients) error
}

type adapter struct {
	env          *common_cli.Env
	clientsMaker ClientsMaker
	cmd          Command

	registrationUDSPath string
	flags               *flag.FlagSet
}

// AdaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func AdaptCommand(env *common_cli.Env, clientsMaker ClientsMaker, cmd Command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
	}

	f := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	f.SetOutput(env.Stderr)
	f.StringVar(&a.registrationUDSPath, "registrationUDSPath", DefaultSocketPath, "Registration API UDS path")
	a.cmd.AppendFlags(f)
	a.flags = f

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		fmt.Fprintln(a.env.Stderr, err)
		return 1
	}

	clients, err := a.clientsMaker(a.registrationUDSPath)
	if err != nil {
		fmt.Fprintln(a.env.Stderr, err)
		return 1
	}

	if err := a.cmd.Run(ctx, a.env, clients); err != nil {
		fmt.Fprintln(a.env.Stderr, err)
		return 1
	}

	return 0
}

func (a *adapter) Help() string {
	return a.flags.Parse([]string{"-h"}).Error()
}

func (a *adapter) Synopsis() string {
	return a.cmd.Synopsis()
}
