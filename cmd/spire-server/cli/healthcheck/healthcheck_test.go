package healthcheck

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/clitest"
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
	s.Equal("Determines server health status", s.cmd.Synopsis())
}

func (s *HealthCheckSuite) TestHelp() {
	s.Equal("flag: help requested", s.cmd.Help())
	s.Equal(healthcheckUsage, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestBadFlags() {
	code := s.cmd.Run([]string{"-badflag"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Equal(`flag provided but not defined: -badflag
`+healthcheckUsage, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsIfEndpointDoesNotExist() {
	code := s.cmd.Run([]string{clitest.AddrArg, clitest.AddrValue})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	spiretest.AssertHasPrefix(s.T(), s.stderr.String(), "Error: server is unhealthy: unable to determine health\n")
}

func (s *HealthCheckSuite) TestFailsIfEndpointDoesNotExistVerbose() {
	code := s.cmd.Run([]string{clitest.AddrArg, clitest.AddrValue, "-verbose"})
	s.NotEqual(0, code, "exit code")
	s.Equal("Checking server health...\n", s.stdout.String(), "stdout")
	spiretest.AssertHasPrefix(s.T(), s.stderr.String(), "Failed to check health: "+clitest.AddrError)
}

func (s *HealthCheckSuite) TestSucceedsIfServingStatusServing() {
	addr := spiretest.StartGRPCServer(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := s.cmd.Run([]string{clitest.AddrArg, clitest.GetAddr(addr)})
	s.Equal(0, code, "exit code")
	s.Equal("Server is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsIfServingStatusServingVerbose() {
	addr := spiretest.StartGRPCServer(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_SERVING))
	})
	code := s.cmd.Run([]string{clitest.AddrArg, clitest.GetAddr(addr), "-verbose"})
	s.Equal(0, code, "exit code")
	s.Equal(`Checking server health...
Server is healthy.
`, s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsIfServiceStatusOther() {
	addr := spiretest.StartGRPCServer(s.T(), func(srv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(srv, withStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING))
	})
	code := s.cmd.Run([]string{clitest.AddrArg, clitest.GetAddr(addr), "-verbose"})
	s.NotEqual(0, code, "exit code")
	s.Equal(`Checking server health...
`, s.stdout.String(), "stdout")
	s.Equal(`Error: server is unhealthy: server returned status "NOT_SERVING"
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
