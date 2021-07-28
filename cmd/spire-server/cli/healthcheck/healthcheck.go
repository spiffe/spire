package healthcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func NewHealthCheckCommand() cli.Command {
	return newHealthCheckCommand(common_cli.DefaultEnv)
}

func newHealthCheckCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(healthCheckCommand))
}

type healthCheckCommand struct {
	shallow bool
	verbose bool
}

func (c *healthCheckCommand) Name() string {
	return "healthcheck"
}

func (c *healthCheckCommand) Synopsis() string {
	return "Determines server health status"
}

func (c *healthCheckCommand) AppendFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.shallow, "shallow", false, "Perform a less stringent health check")
	fs.BoolVar(&c.verbose, "verbose", false, "Print verbose information")
}

func (c *healthCheckCommand) Run(ctx context.Context, env *common_cli.Env, client util.ServerClient) error {
	if err := c.run(ctx, env, client); err != nil {
		return fmt.Errorf("server is unhealthy: %w", err)
	}
	return env.Println("Server is healthy.")
}

func (c *healthCheckCommand) run(ctx context.Context, env *common_cli.Env, client util.ServerClient) error {
	if c.verbose {
		if err := env.Println("Checking server health..."); err != nil {
			return err
		}
	}

	healthClient := client.NewHealthClient()
	resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		if c.verbose {
			// Ignore error since a failure to write to stderr cannot very well
			// be reported
			_ = env.ErrPrintf("Failed to check health: %v\n", err)
		}
		return errors.New("unable to determine health")
	}

	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("server returned status %q", resp.Status)
	}

	return nil
}
