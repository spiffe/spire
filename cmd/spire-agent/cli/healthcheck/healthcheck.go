package healthcheck

import (
	"errors"
	"flag"
	"net"
	"time"

	"github.com/mitchellh/cli"
	api_workload "github.com/spiffe/spire/api/workload"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewHealthCheckCommand() cli.Command {
	return newHealthCheckCommand(common_cli.DefaultEnv)
}

func newHealthCheckCommand(env *common_cli.Env) *healthCheckCommand {
	return &healthCheckCommand{
		env:     env,
		timeout: common_cli.DurationFlag(time.Second * 5),
	}
}

type healthCheckCommand struct {
	env *common_cli.Env

	socketPath string
	timeout    common_cli.DurationFlag
	shallow    bool
	verbose    bool
}

func (c *healthCheckCommand) Help() string {
	// ignoring parsing errors since "-h" is always supported by the flags package
	_ = c.parseFlags([]string{"-h"})
	return ""
}

func (c *healthCheckCommand) Synopsis() string {
	return "Determines agent health status"
}

func (c *healthCheckCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(); err != nil {
		// Ignore error since a failure to write to stderr cannot very well
		// be reported
		_ = c.env.ErrPrintln(err)
		return 1
	}
	return 0
}

func (c *healthCheckCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to Workload API socket")
	fs.BoolVar(&c.shallow, "shallow", false, "Perform a less stringent health check")
	fs.BoolVar(&c.verbose, "verbose", false, "Print verbose information")
	return fs.Parse(args)
}

func (c *healthCheckCommand) run() error {
	addr := &net.UnixAddr{
		Name: c.socketPath,
		Net:  "unix",
	}

	if c.verbose {
		c.env.Printf("Contacting Workload API...\n")
	}

	client := api_workload.NewX509Client(&api_workload.X509ClientConfig{
		Addr:        addr,
		FailOnError: true,
	})
	defer client.Stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start()
	}()

	select {
	case err := <-errCh:
		if c.verbose {
			c.env.Printf("Workload API returned %s\n", err)
		}
		if status.Code(err) == codes.Unavailable {
			return errors.New("Agent is unavailable.") //nolint: golint // error is (ab)used for CLI output
		}
	case <-client.UpdateChan():
		if c.verbose {
			if err := c.env.Println("SVID received over Workload API."); err != nil {
				return err
			}
		}
	}

	if err := c.env.Println("Agent is healthy."); err != nil {
		return err
	}
	return nil
}
