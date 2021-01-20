package healthcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
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
	env *common_cli.Env

	socketPath string
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
	fs.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to Workload API socket")
	fs.BoolVar(&c.shallow, "shallow", false, "Perform a less stringent health check")
	fs.BoolVar(&c.verbose, "verbose", false, "Print verbose information")
	return fs.Parse(args)
}

func (c *healthCheckCommand) run() error {
	if c.verbose {
		c.env.Printf("Checking agent health...\n")
	}

	conn, err := dial.Dial(context.Background(), &net.UnixAddr{
		Name: c.socketPath,
		Net:  "unix",
	})
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
