package healthcheck

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type healthCheckTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command
}

func setupTest() *healthCheckTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	return &healthCheckTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		cmd: newHealthCheckCommand(&common_cli.Env{
			Stdin:  stdin,
			Stdout: stdout,
			Stderr: stderr,
		}),
	}
}

func TestSynopsis(t *testing.T) {
	test := setupTest()
	require.Equal(t, "Determines agent health status", test.cmd.Synopsis())
}

func TestHelp(t *testing.T) {
	test := setupTest()

	require.Empty(t, test.cmd.Help())
	require.Equal(t, usage, test.stderr.String(), "stderr")
}

func TestBadFlags(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"-badflag"})
	require.NotEqual(t, 0, code, "exit code")
	require.Empty(t, test.stdout.String(), "stdout")
	require.Equal(t, "flag provided but not defined: -badflag\n"+usage, test.stderr.String(), "stderr")
}

func TestFailsOnUnavailable(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{socketAddrArg, socketAddrUnavailable})
	require.NotEqual(t, 0, code, "exit code")
	require.Empty(t, test.stdout.String(), "stdout")
	require.Equal(t, "Agent is unhealthy: unable to determine health\n", test.stderr.String(), "stderr")
}

func TestFailsOnUnavailableVerbose(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{socketAddrArg, socketAddrUnavailable, "-verbose"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
`, test.stdout.String(), "stdout")
	require.Equal(t, unavailableErr, test.stderr.String())
}

func TestSucceedsIfServingStatusServing(t *testing.T) {
	test := setupTest()

	socketAddr := startGRPCSocketServer(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{socketAddrArg, socketAddr})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, "Agent is healthy.\n", test.stdout.String(), "stdout")
	require.Empty(t, test.stderr.String(), "stderr")
}

func TestSucceedsIfServingStatusServingVerbose(t *testing.T) {
	test := setupTest()

	socketAddr := startGRPCSocketServer(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{socketAddrArg, socketAddr, "-verbose"})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
Agent is healthy.
`, test.stdout.String(), "stdout")
	require.Empty(t, test.stderr.String(), "stderr")
}

func TestFailsIfServiceStatusOther(t *testing.T) {
	test := setupTest()

	socketAddr := startGRPCSocketServer(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING))
	})
	code := test.cmd.Run([]string{socketAddrArg, socketAddr})
	require.NotEqual(t, 0, code, "exit code")
	require.Empty(t, test.stdout.String(), "stdout")
	require.Equal(t, `Agent is unhealthy: agent returned status "NOT_SERVING"
`, test.stderr.String(), "stderr")
}

func withStatus(status grpc_health_v1.HealthCheckResponse_ServingStatus) healthServer {
	return healthServer{status: status}
}

type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	status grpc_health_v1.HealthCheckResponse_ServingStatus
	err    error
}

func (s healthServer) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &grpc_health_v1.HealthCheckResponse{
		Status: s.status,
	}, nil
}
