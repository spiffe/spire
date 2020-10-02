package util

import (
	"context"
	"flag"
	"fmt"
	"net"

	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"google.golang.org/grpc"
)

const (
	DefaultSocketPath = "/tmp/spire-registration.sock"
)

func NewRegistrationClient(socketPath string) (registration.RegistrationClient, error) {
	conn, err := Dial(socketPath)
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}

func Dial(socketPath string) (*grpc.ClientConn, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return grpc.Dial(socketPath,
		grpc.WithInsecure(),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithReturnConnectionError())
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}

type ServerClient interface {
	Release()
	NewAgentClient() agent.AgentClient
	NewBundleClient() bundle.BundleClient
}

func NewServerClient(socketPath string) (ServerClient, error) {
	conn, err := Dial(socketPath)
	if err != nil {
		return nil, err
	}
	return &serverClient{conn: conn}, nil
}

type serverClient struct {
	conn *grpc.ClientConn
}

func (c *serverClient) Release() {
	c.conn.Close()
}

func (c *serverClient) NewAgentClient() agent.AgentClient {
	return agent.NewAgentClient(c.conn)
}

func (c *serverClient) NewBundleClient() bundle.BundleClient {
	return bundle.NewBundleClient(c.conn)
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

// Command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type Command interface {
	Name() string
	Synopsis() string
	AppendFlags(*flag.FlagSet)
	Run(context.Context, *common_cli.Env, ServerClient) error
}

type Adapter struct {
	env *common_cli.Env
	cmd Command

	flags               *flag.FlagSet
	registrationUDSPath string
}

// AdaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func AdaptCommand(env *common_cli.Env, cmd Command) *Adapter {
	a := &Adapter{
		cmd: cmd,
		env: env,
	}

	f := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	f.SetOutput(env.Stderr)
	f.StringVar(&a.registrationUDSPath, "registrationUDSPath", DefaultSocketPath, "Registration API UDS path")
	a.cmd.AppendFlags(f)
	a.flags = f

	return a
}

func (a *Adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		fmt.Fprintln(a.env.Stderr, err)
		return 1
	}

	client, err := NewServerClient(a.registrationUDSPath)
	if err != nil {
		fmt.Fprintln(a.env.Stderr, err)
		return 1
	}
	defer client.Release()

	if err := a.cmd.Run(ctx, a.env, client); err != nil {
		fmt.Fprintln(a.env.Stderr, err)
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
