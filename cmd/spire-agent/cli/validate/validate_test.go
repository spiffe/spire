package validate

import (
	"bytes"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/suite"
)

// NOTE: Since Run() in this package is a wrapper
// using some functions in run package, Do not test here.

func TestValidate(t *testing.T) {
	suite.Run(t, new(ValidateSuite))
}

type ValidateSuite struct {
	suite.Suite

	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command
}

func (s *ValidateSuite) SetupTest() {
	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	s.stderr = new(bytes.Buffer)

	s.cmd = newValidateCommand(&common_cli.Env{
		Stdin:  s.stdin,
		Stdout: s.stdout,
		Stderr: s.stderr,
	})
}

func (s *ValidateSuite) TestSynopsis() {
	s.Equal("Validates a SPIRE agent configuration file", s.cmd.Synopsis())
}

func (s *ValidateSuite) TestHelp() {
	s.Equal("flag: help requested", s.cmd.Help())
	s.Contains(s.stderr.String(), "Usage of validate:", "stderr")
}

func (s *ValidateSuite) TestBadFlags() {
	code := s.cmd.Run([]string{"-badflag"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Contains(s.stderr.String(), "flag provided but not defined: -badflag", "stderr")
}
