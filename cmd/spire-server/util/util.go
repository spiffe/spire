package util

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strings"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	api_types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

const (
	DefaultSocketPath = "/tmp/spire-server/private/api.sock"
)

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
	NewAgentClient() agentv1.AgentClient
	NewBundleClient() bundlev1.BundleClient
	NewEntryClient() entryv1.EntryClient
	NewSVIDClient() svidv1.SVIDClient
	NewHealthClient() grpc_health_v1.HealthClient
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

func (c *serverClient) NewAgentClient() agentv1.AgentClient {
	return agentv1.NewAgentClient(c.conn)
}

func (c *serverClient) NewBundleClient() bundlev1.BundleClient {
	return bundlev1.NewBundleClient(c.conn)
}

func (c *serverClient) NewEntryClient() entryv1.EntryClient {
	return entryv1.NewEntryClient(c.conn)
}

func (c *serverClient) NewSVIDClient() svidv1.SVIDClient {
	return svidv1.NewSVIDClient(c.conn)
}

func (c *serverClient) NewHealthClient() grpc_health_v1.HealthClient {
	return grpc_health_v1.NewHealthClient(c.conn)
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

	flags      *flag.FlagSet
	socketPath string
}

// AdaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func AdaptCommand(env *common_cli.Env, cmd Command) *Adapter {
	a := &Adapter{
		cmd: cmd,
		env: env,
	}

	f := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	f.SetOutput(env.Stderr)
	f.StringVar(&a.socketPath, "socketPath", DefaultSocketPath, "Path to the SPIRE Server API socket")
	a.cmd.AppendFlags(f)
	a.flags = f

	return a
}

func (a *Adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		return 1
	}

	client, err := NewServerClient(a.socketPath)
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

// parseSelector parses a CLI string from type:value into a selector type.
// Everything to the right of the first ":" is considered a selector value.
func ParseSelector(str string) (*api_types.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &api_types.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}
