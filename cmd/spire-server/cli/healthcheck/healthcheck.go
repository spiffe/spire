package healthcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc/health/grpc_health_v1"
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
	return "Determines server health status"
}

func (c *healthCheckCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(); err != nil {
		// Ignore error since a failure to write to stderr cannot very well be
		// reported
		_ = c.env.ErrPrintf("Server is unhealthy: %v\n", err)
		return 1
	}
	if err := c.env.Println("Server is healthy."); err != nil {
		return 1
	}
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

func (c *healthCheckCommand) run() error {
	if c.verbose {
		if err := c.env.Println("Checking server health..."); err != nil {
			return err
		}
	}

	client, err := util.NewServerClient(c.socketPath)
	if err != nil {
		if c.verbose {
			// Ignore error since a failure to write to stderr cannot very well
			// be reported
			_ = c.env.ErrPrintf("Failed to create client: %v\n", err)
		}
		return errors.New("cannot create health client")
	}
	defer client.Release()

	healthClient := client.NewHealthClient()
	resp, err := healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		if c.verbose {
			// Ignore error since a failure to write to stderr cannot very well
			// be reported
			_ = c.env.ErrPrintf("Failed to check health: %v\n", err)
		}
		return errors.New("unable to determine health")
	}

	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("server returned status %q", resp.Status)
	}

	return nil
}
