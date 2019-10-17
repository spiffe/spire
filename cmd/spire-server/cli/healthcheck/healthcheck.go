package healthcheck

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/common"
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
	c.parseFlags([]string{"-h"})
	return ""
}

func (c *healthCheckCommand) Synopsis() string {
	return "Determines server health status"
}

func (c *healthCheckCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(args); err != nil {
		c.env.ErrPrintf("Server is unhealthy: %v\n", err)
		return 1
	}
	c.env.Println("Server is healthy.")
	return 0
}

func (c *healthCheckCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.StringVar(&c.socketPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	fs.BoolVar(&c.shallow, "shallow", false, "Perform a less stringent health check")
	fs.BoolVar(&c.verbose, "verbose", false, "Print verbose information")
	return fs.Parse(args)
}

func (c *healthCheckCommand) run(args []string) error {
	if c.verbose {
		c.env.Println("Fetching bundle via Registration API...")
	}

	client, err := util.NewRegistrationClient(c.socketPath)
	if err != nil {
		if c.verbose {
			c.env.ErrPrintf("Failed to create client: %v\n", err)
		}
		return errors.New("cannot create registration client")
	}

	// Currently using the ability to fetch a bundle as the health check. This
	// **could** be problematic if the Upstream CA signing process is lengthy.
	// As currently coded however, the registration API isn't served until after
	// the server CA has been signed by upstream.
	if _, err := client.FetchBundle(context.Background(), &common.Empty{}); err != nil {
		if c.verbose {
			c.env.ErrPrintf("Failed to fetch bundle: %v\n", err)
		}
		return errors.New("unable to fetch bundle")
	}
	if c.verbose {
		c.env.Println("Successfully fetched bundle.")
	}

	return nil
}
