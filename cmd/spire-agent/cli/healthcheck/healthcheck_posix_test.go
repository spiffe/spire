//go:build !windows
// +build !windows

package healthcheck

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestHelp(t *testing.T) {
	test := setupTest()

	require.Equal(t, "", test.cmd.Help())
	require.Equal(t, `Usage of health:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Agent API socket (default "/tmp/spire-agent/public/api.sock")
  -verbose
    	Print verbose information
`, test.stderr.String(), "stderr")
}

func TestBadFlags(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"-badflag"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, "", test.stdout.String(), "stdout")
	require.Equal(t, `flag provided but not defined: -badflag
Usage of health:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Agent API socket (default "/tmp/spire-agent/public/api.sock")
  -verbose
    	Print verbose information
`, test.stderr.String(), "stderr")
}

func TestFailsOnUnavailable(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"--socketPath", "/tmp/doesnotexist.sock"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, "", test.stdout.String(), "stdout")
	require.Equal(t, "Agent is unhealthy: unable to determine health\n", test.stderr.String(), "stderr")
}

func TestFailsOnUnavailableVerbose(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"--socketPath", "/tmp/doesnotexist.sock", "--verbose"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
`, test.stdout.String(), "stdout")

	expectSocketPath, err := filepath.Abs("/tmp/doesnotexist.sock")
	require.NoError(t, err)
	expectSocketPath = filepath.ToSlash(expectSocketPath)

	expectPrefix := fmt.Sprintf(`Failed to check health: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial unix %s: `, expectSocketPath)
	spiretest.AssertHasPrefix(t, test.stderr.String(), expectPrefix)
}

func TestSucceedsIfServingStatusServing(t *testing.T) {
	test := setupTest()

	socketPath := spiretest.StartGRPCSocketServerOnTempUDSSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{"--socketPath", socketPath})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, "Agent is healthy.\n", test.stdout.String(), "stdout")
	require.Equal(t, "", test.stderr.String(), "stderr")
}

func TestSucceedsIfServingStatusServingVerbose(t *testing.T) {
	test := setupTest()

	socketPath := spiretest.StartGRPCSocketServerOnTempUDSSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{"--socketPath", socketPath, "--verbose"})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
Agent is healthy.
`, test.stdout.String(), "stdout")
	require.Equal(t, "", test.stderr.String(), "stderr")
}

func TestFailsIfServiceStatusOther(t *testing.T) {
	test := setupTest()

	socketPath := spiretest.StartGRPCSocketServerOnTempUDSSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING))
	})
	code := test.cmd.Run([]string{"--socketPath", socketPath})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, "", test.stdout.String(), "stdout")
	require.Equal(t, `Agent is unhealthy: agent returned status "NOT_SERVING"
`, test.stderr.String(), "stderr")
}
