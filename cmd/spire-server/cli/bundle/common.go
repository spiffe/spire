package bundle

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
)

var (
	// this is the default environment used by commands
	defaultEnv = &env{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
)

type clients struct {
	r registration.RegistrationClient
}

type clientsMaker func(registrationUDSPath string) (*clients, error)

// newClients is the default client maker
func newClients(registrationUDSPath string) (*clients, error) {
	registrationClient, err := util.NewRegistrationClient(registrationUDSPath)
	if err != nil {
		return nil, err
	}

	return &clients{
		r: registrationClient,
	}, nil
}

// command is a common interface for commands in this package. the adapter
// can adapter this interface to the Command interface from github.com/mitchellh/cli.
type command interface {
	name() string
	synopsis() string
	appendFlags(*flag.FlagSet)
	run(context.Context, *env, *clients) error
}

type adapter struct {
	env          *env
	clientsMaker clientsMaker
	cmd          command

	registrationUDSPath string
	flags               *flag.FlagSet
}

// adaptCommand converts a command into one conforming to the Command interface from github.com/mitchellh/cli
func adaptCommand(env *env, clientsMaker clientsMaker, cmd command) *adapter {
	a := &adapter{
		clientsMaker: clientsMaker,
		cmd:          cmd,
		env:          env,
	}

	f := flag.NewFlagSet(cmd.name(), flag.ContinueOnError)
	f.SetOutput(env.stderr)
	f.StringVar(&a.registrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS Path")
	a.cmd.appendFlags(f)
	a.flags = f

	return a
}

func (a *adapter) Run(args []string) int {
	ctx := context.Background()

	if err := a.flags.Parse(args); err != nil {
		fmt.Fprintln(a.env.stderr, err)
		return 1
	}

	clients, err := a.clientsMaker(a.registrationUDSPath)
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
