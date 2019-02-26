package healthcheck

import (
	"bytes"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/test/fakes/fakeworkloadapi"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	s.Equal("Agent is unavailable.\n", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsOnUnavailableVerbose() {
	code := s.cmd.Run([]string{"--socketPath", "doesnotexist.sock", "--verbose"})
	s.NotEqual(0, code, "exit code")
	s.Equal(`Contacting Workload API...
Workload API returned rpc error: code = Unavailable desc = all SubConns are in TransientFailure, latest connection error: connection error: desc = "transport: Error while dialing dial unix doesnotexist.sock: connect: no such file or directory"
`, s.stdout.String(), "stdout")
	s.Equal("Agent is unavailable.\n", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsOnPermissionDenied() {
	w := s.makeFailedWorkloadAPI(status.Error(codes.PermissionDenied, "permission denied"))
	defer w.Close()
	code := s.cmd.Run([]string{"--socketPath", w.Addr().Name})
	s.Equal(0, code, "exit code")
	s.Equal("Agent is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsOnUnknown() {
	w := s.makeFailedWorkloadAPI(status.Error(codes.Unknown, "unknown"))
	defer w.Close()
	code := s.cmd.Run([]string{"--socketPath", w.Addr().Name})
	s.Equal(0, code, "exit code")
	s.Equal("Agent is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsOnGoodResponse() {
	w := s.makeGoodWorkloadAPI()
	defer w.Close()
	code := s.cmd.Run([]string{"--socketPath", w.Addr().Name})
	s.Equal(0, code, "exit code")
	s.Equal("Agent is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsOnGoodResponseVerbose() {
	w := s.makeGoodWorkloadAPI()
	defer w.Close()
	code := s.cmd.Run([]string{"--socketPath", w.Addr().Name, "--verbose"})
	s.Equal(0, code, "exit code")
	s.Equal(`Contacting Workload API...
SVID received over Workload API.
Agent is healthy.
`, s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) makeFailedWorkloadAPI(err error) *fakeworkloadapi.WorkloadAPI {
	return fakeworkloadapi.New(s.T(), fakeworkloadapi.FetchX509SVIDErrorOnce(err))
}

func (s *HealthCheckSuite) makeGoodWorkloadAPI() *fakeworkloadapi.WorkloadAPI {
	return fakeworkloadapi.New(s.T(), fakeworkloadapi.FetchX509SVIDResponses(&workload.X509SVIDResponse{}))
}
