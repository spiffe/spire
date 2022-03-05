//go:build windows
// +build windows

package healthcheck

import (
	"fmt"
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
  -tcpSocketPort int
    	TCP port number of the SPIRE Agent API socket (default 8082)
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
  -tcpSocketPort int
    	TCP port number of the SPIRE Agent API socket (default 8082)
  -verbose
    	Print verbose information
`, test.stderr.String(), "stderr")
}

func TestFailsOnUnavailable(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"--tcpSocketPort", "8083"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, "", test.stdout.String(), "stdout")
	require.Equal(t, "Agent is unhealthy: unable to determine health\n", test.stderr.String(), "stderr")
}

func TestFailsOnUnavailableVerbose(t *testing.T) {
	test := setupTest()

	tcpSocketPort := "8083"
	code := test.cmd.Run([]string{"--tcpSocketPort", tcpSocketPort, "--verbose"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
`, test.stdout.String(), "stdout")

	require.Contains(t,
		test.stderr.String(),
		fmt.Sprintf(`Failed to check health: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 127.0.0.1:%s: connectex: No connection could be made because the target machine actively refused it.`, tcpSocketPort))
}

func TestSucceedsIfServingStatusServing(t *testing.T) {
	test := setupTest()

	tcpAddr := spiretest.StartGRPCSocketServerOnFreeTCPSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{"--tcpSocketPort", fmt.Sprintf("%d", tcpAddr.Port)})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, "Agent is healthy.\n", test.stdout.String(), "stdout")
	require.Equal(t, "", test.stderr.String(), "stderr")
}

func TestSucceedsIfServingStatusServingVerbose(t *testing.T) {
	test := setupTest()

	tcpAddr := spiretest.StartGRPCSocketServerOnFreeTCPSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := test.cmd.Run([]string{"--tcpSocketPort", fmt.Sprintf("%d", tcpAddr.Port), "--verbose"})
	require.Equal(t, 0, code, "exit code")
	require.Equal(t, `Checking agent health...
Agent is healthy.
`, test.stdout.String(), "stdout")
	require.Equal(t, "", test.stderr.String(), "stderr")
}

func TestFailsIfServiceStatusOther(t *testing.T) {
	test := setupTest()

	tcpAddr := spiretest.StartGRPCSocketServerOnFreeTCPSocket(t, func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING))
	})
	code := test.cmd.Run([]string{"--tcpSocketPort", fmt.Sprintf("%d", tcpAddr.Port), "--verbose"})
	require.NotEqual(t, 0, code, "exit code")
	require.Equal(t, `Agent is unhealthy: agent returned status "NOT_SERVING"
`, test.stderr.String(), "stderr")
}
