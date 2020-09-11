package healthcheck

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
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
	s.Equal("", s.cmd.Help())
	s.Equal(`Usage of health:
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -shallow
    	Perform a less stringent health check
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
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -shallow
    	Perform a less stringent health check
  -verbose
    	Print verbose information
`, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsIfBundleCannotBeFetched() {
	code := s.cmd.Run([]string{"--registrationUDSPath", "doesnotexist.sock"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Equal("Server is unhealthy: unable to fetch bundle\n", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestFailsIfBundleCannotBeFetchedVerbose() {
	code := s.cmd.Run([]string{"--registrationUDSPath", "doesnotexist.sock", "--verbose"})
	s.NotEqual(0, code, "exit code")
	s.Equal(`Fetching bundle via Registration API...
`, s.stdout.String(), "stdout")
	s.Equal(`Failed to fetch bundle: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial unix doesnotexist.sock: connect: no such file or directory"
Server is unhealthy: unable to fetch bundle
`, s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsIfBundleFetched() {
	socketPath := spiretest.StartRegistrationAPIOnTempSocket(s.T(), withBundle{})
	code := s.cmd.Run([]string{"--registrationUDSPath", socketPath})
	s.Equal(0, code, "exit code")
	s.Equal("Server is healthy.\n", s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

func (s *HealthCheckSuite) TestSucceedsIfBundleFetchedVerbose() {
	socketPath := spiretest.StartRegistrationAPIOnTempSocket(s.T(), withBundle{})
	code := s.cmd.Run([]string{"--registrationUDSPath", socketPath, "--verbose"})
	s.Equal(0, code, "exit code")
	s.Equal(`Fetching bundle via Registration API...
Successfully fetched bundle.
Server is healthy.
`, s.stdout.String(), "stdout")
	s.Equal("", s.stderr.String(), "stderr")
}

type withBundle struct {
	registration.RegistrationServer
}

func (withBundle) FetchBundle(context.Context, *common.Empty) (*registration.Bundle, error) {
	return &registration.Bundle{}, nil
}
