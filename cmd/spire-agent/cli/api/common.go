package api

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	workload_dial "github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc/metadata"
)

var (
	// this is the default environment used by commands
	defaultEnv = &env{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
)

const (
	defaultSocketPath = "/tmp/agent.sock"
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
	run(context.Context, *env, *workloadClient) error
}

type adapter struct {
	env          *env
	clientsMaker workloadClientMaker
	cmd          command

	socketPath string
	timeout    durationFlag
	flags      *flag.FlagSet
}

// adaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func adaptCommand(env *env, clientsMaker workloadClientMaker, cmd command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
		timeout:      durationFlag(time.Second),
	}

	fs := flag.NewFlagSet(cmd.name(), flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	fs.StringVar(&a.socketPath, "socketPath", defaultSocketPath, "Path to Workload API socket")
	fs.Var(&a.timeout, "timeout", "Time to wait for a response")
	a.cmd.appendFlags(fs)
	a.flags = fs

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	clients, err := a.clientsMaker(ctx, a.socketPath, time.Duration(a.timeout))
	if err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	if err := a.cmd.run(ctx, a.env, clients); err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	return 0
}

func (a *adapter) Help() string {
	return a.flags.Parse([]string{"-h"}).Error()
}

func (a *adapter) Synopsis() string {
	return a.cmd.synopsis()
}

// env provides input and output facilities to commands
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (e *env) Printf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.stdout, format, args...)
	return err
}

func (e *env) Println(args ...interface{}) error {
	_, err := fmt.Fprintln(e.stdout, args...)
	return err
}

func (e *env) ErrPrintf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.stderr, format, args...)
	return err
}

func (e *env) ErrPrintln(args ...interface{}) error {
	_, err := fmt.Fprintln(e.stderr, args...)
	return err
}

type stringsFlag []string

func (f stringsFlag) String() string {
	return strings.Join(f, ",")
}

func (f *stringsFlag) Set(v string) error {
	*f = strings.Split(v, ",")
	return nil
}

type durationFlag time.Duration

func (f durationFlag) String() string {
	return time.Duration(f).String()
}

func (f *durationFlag) Set(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	*f = durationFlag(d)
	return nil
}
