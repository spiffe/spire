package healthcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func NewHealthCheckCommand() cli.Command {
	return newHealthCheckCommand(common_cli.DefaultEnv)
}

func newHealthCheckCommand(env *common_cli.Env) *healthCheckCommand {
	return &healthCheckCommand{
		env: env,
	}
}

type healthCheckCommand struct {
	healthCheckCommandOS // os specific

	env *common_cli.Env

	shallow bool
	verbose bool
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
		// Ignore error since a failure to write to stderr cannot very well be
		// reported
		_ = c.env.ErrPrintf("Agent is unhealthy: %v\n", err)
		return 1
	}
	if err := c.env.Println("Agent is healthy."); err != nil {
		return 1
	}
	return 0
}

func (c *healthCheckCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.BoolVar(&c.shallow, "shallow", false, "Perform a less stringent health check")
	fs.BoolVar(&c.verbose, "verbose", false, "Print verbose information")
	c.addOSFlags(fs)
	return fs.Parse(args)
}

func (c *healthCheckCommand) run() error {
	if c.verbose {
		c.env.Printf("Checking agent health...\n")
	}

	addr, err := c.getAddr()
	if err != nil {
		return err
	}
	target, err := util.GetTargetName(addr)
	if err != nil {
		return err
	}
	conn, err := util.GRPCDialContext(context.Background(), target)
	if err != nil {
		return err
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
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
		return fmt.Errorf("agent returned status %q", resp.Status)
	}

	return nil
}
