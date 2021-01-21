package healthcheck

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthCheck(t *testing.T) {
	suite.Run(t, new(HealthCheckSuite))
}

type HealthCheckSuite struct {
	suite.Suite

	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command
}

func (s *HealthCheckSuite) SetupTest() {
	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	s.stderr = new(bytes.Buffer)

	s.cmd = newHealthCheckCommand(&common_cli.Env{
		Stdin:  s.stdin,
		Stdout: s.stdout,
		Stderr: s.stderr,
	})
}

func (s *HealthCheckSuite) TestSynopsis() {
	s.Equal("Determines agent health status", s.cmd.Synopsis())
}

func (s *HealthCheckSuite) TestHelp() {
	s.Equal("", s.cmd.Help())
	s.Equal(`Usage of health:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to Workload API socket (default "/tmp/agent.sock")
  -verbose
    	Print verbose information
`, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestBadFlags() {
	code := s.cmd.Run([]string{"-badflag"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Equal(`flag provided but not defined: -badflag
Usage of health:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to Workload API socket (default "/tmp/agent.sock")
  -verbose
    	Print verbose information
`, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsOnUnavailable() {
	code := s.cmd.Run([]string{"--socketPath", "doesnotexist.sock"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Equal("Agent is unhealthy: unable to determine health\n", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsOnUnavailableVerbose() {
	code := s.cmd.Run([]string{"--socketPath", "doesnotexist.sock", "--verbose"})
	s.NotEqual(0, code, "exit code")
	s.Equal(`Checking agent health...
`, s.stdout.String(), "stdout")
	s.Equal(`Failed to check health: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial unix doesnotexist.sock: connect: no such file or directory"
Agent is unhealthy: unable to determine health
`, s.stderr.String(), "stdout")
}

func (s *HealthCheckSuite) TestSucceedsIfServingStatusServing() {
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := s.cmd.Run([]string{"--socketPath", socketPath})
	s.Equal(0, code, "exit code")
	s.Equal("Agent is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsIfServingStatusServingVerbose() {
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := s.cmd.Run([]string{"--socketPath", socketPath, "--verbose"})
	s.Equal(0, code, "exit code")
	s.Equal(`Checking agent health...
Agent is healthy.
`, s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsIfServiceStatusOther() {
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING))
	})
	code := s.cmd.Run([]string{"--socketPath", socketPath})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Equal(`Agent is unhealthy: agent returned status "NOT_SERVING"
`, s.stderr.String(), "stderr")
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
