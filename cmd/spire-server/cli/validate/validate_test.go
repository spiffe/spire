package validate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	s.Equal("Validates a SPIRE server configuration file", s.cmd.Synopsis())
}

func (s *ValidateSuite) TestHelp() {
	s.Equal("flag: help requested", s.cmd.Help())
	s.Contains(s.stderr.String(), "Usage of validate:")
}

func (s *ValidateSuite) TestBadFlags() {
	code := s.cmd.Run([]string{"-badflag"})
	s.NotEqual(0, code, "exit code")
	s.Equal("", s.stdout.String(), "stdout")
	s.Contains(s.stderr.String(), "flag provided but not defined: -badflag")
}

// Validating the config of a running server must not disturb that server's log.
// log_file from the config file otherwise overrides the io.Discard writer this
// command passes, so validate would open the live log and could rotate it.
func (s *ValidateSuite) TestDoesNotTouchLogFile() {
	configDir := s.T().TempDir()
	logFile := filepath.Join(configDir, "server.log")

	config := fmt.Sprintf(`
server {
	bind_address = "127.0.0.1"
	bind_port = "8081"
	trust_domain = "example.org"
	data_dir = %q
	log_file = %q
	log_file_rotation {
		max_size_mb = 1
		max_files = 1
	}
}

plugins {
	DataStore "sql" {
		plugin_data {
			database_type = "sqlite3"
			connection_string = %q
		}
	}
	KeyManager "memory" {
		plugin_data = {}
	}
}
`, configDir, logFile, filepath.Join(configDir, "datastore.sqlite3"))

	confPath := filepath.Join(configDir, "server.conf")
	s.Require().NoError(os.WriteFile(confPath, []byte(config), 0600))

	s.cmd.Run([]string{"-config", confPath})

	s.NoFileExists(logFile, "validate must not create or write the configured log file")
}
