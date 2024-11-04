//go:build !windows

package run

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	configFile      = "../../../../test/fixture/config/server_good_posix.conf"
	startConfigFile = "../../../../test/fixture/config/server_run_start_posix.conf"
	crashConfigFile = "../../../../test/fixture/config/server_run_crash_posix.conf"
)

func TestCommand_Run(t *testing.T) {
	availablePort, err := getAvailablePort()
	require.NoError(t, err)
	testTempDir := t.TempDir()
	testLogFile := testTempDir + "/spire-server.log"

	type fields struct {
		logOptions         []log.Option
		env                *commoncli.Env
		allowUnknownConfig bool
	}
	type args struct {
		args              []string
		killServerOnStart bool
	}
	type want struct {
		code           int
		dataDirCreated string
		stderrContent  string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		configLoaded bool
		want         want
	}{
		{
			name: "don't create any dir when error loading nonexistent config",
			args: args{
				args: []string{},
			},
			fields: fields{
				logOptions: []log.Option{log.WithOutputFile(testLogFile)},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: false,
			want: want{
				code:          1,
				stderrContent: "could not find config file",
			},
		},
		{
			name: "don't create any dir when error loading invalid config",
			args: args{
				args: []string{
					"-config", startConfigFile,
					"-serverPort", availablePort,
					"-namedPipeName", "\\spire-agent\\public\\api",
				},
			},
			fields: fields{
				logOptions: []log.Option{log.WithOutputFile(testLogFile)},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: false,
			want: want{
				code:          1,
				stderrContent: "flag provided but not defined: -namedPipeName",
			},
		},
		{
			name: "create data dir when config is loaded and server crashes",
			args: args{
				args: []string{
					"-config", crashConfigFile,
					"-serverPort", availablePort,
					"-dataDir", fmt.Sprintf("%s/crash/data", testTempDir),
					"-expandEnv", "true",
				},
			},
			fields: fields{
				logOptions: []log.Option{log.WithOutputFile(testLogFile)},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: true,
			want: want{
				code:           1,
				dataDirCreated: fmt.Sprintf("%s/crash/data", testTempDir),
			},
		},
		{
			name: "create data dir when config is loaded and server stops",
			args: args{
				args: []string{
					"-serverPort", availablePort,
					"-config", startConfigFile,
					"-dataDir", fmt.Sprintf("%s/data", testTempDir),
					"-expandEnv", "true",
				},
				killServerOnStart: true,
			},
			fields: fields{
				logOptions: []log.Option{log.WithOutputFile(testLogFile)},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: true,
			want: want{
				code:           0,
				dataDirCreated: fmt.Sprintf("%s/data", testTempDir),
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_ = fflag.Unload()
			require.NoError(t, os.Setenv("SPIRE_SERVER_TEST_DATA_CONNECTION", fmt.Sprintf("%s/data/datastore.sqlite3", testTempDir)))
			os.Remove(testLogFile)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}

			if testCase.args.killServerOnStart {
				killServerOnStart(t, testLogFile)
			}

			code := cmd.Run(testCase.args.args)

			assert.Equal(t, testCase.want.code, code)
			if testCase.want.stderrContent == "" {
				assert.Empty(t, testCase.fields.env.Stderr.(*bytes.Buffer).String())
			} else {
				assert.Contains(t, testCase.fields.env.Stderr.(*bytes.Buffer).String(), testCase.want.stderrContent)
			}
			if testCase.want.dataDirCreated != "" {
				assert.DirExistsf(t, testCase.want.dataDirCreated, "data directory should be created")
				currentUmask := unix.Umask(0)
				assert.Equalf(t, currentUmask, 0o027, "spire-server process should have been created with 0027 umask")
			} else {
				assert.NoDirExistsf(t, testCase.want.dataDirCreated, "data directory should not be created")
			}
		})
	}
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-bindAddress=127.0.0.1",
		"-socketPath=/tmp/flag.sock",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.SocketPath, "/tmp/flag.sock")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.LogLevel, "INFO")
}

func killServerOnStart(t *testing.T, testLogFile string) {
	go func() {
		serverStartWaitingTimeout := 10 * time.Second
		serverStartWaitingInterval := 100 * time.Millisecond
		ticker := time.NewTicker(serverStartWaitingInterval)
		timer := time.NewTimer(serverStartWaitingTimeout)
	waitingLoop:
		for {
			select {
			case <-timer.C:
				panic("server did not start in time")
			case <-ticker.C:
				logs, err := os.ReadFile(testLogFile)
				if err != nil {
					continue
				}
				if strings.Contains(string(logs), "Starting Server APIs") {
					timer.Stop()
					break waitingLoop
				}
			}
		}

		err := unix.Kill(unix.Getpid(), unix.SIGINT)
		if err != nil {
			t.Errorf("Failed to kill process: %v", err)
		}
	}()
}

func mergeInputCasesOS(*testing.T) []mergeInputCase {
	return []mergeInputCase{
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-socketPath=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliFlags: []string{"-socketPath=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.SocketPath)
			},
		},
	}
}

func newServerConfigCasesOS(t *testing.T) []newServerConfigCase {
	testDir := t.TempDir()

	return []newServerConfigCase{
		{
			msg: "socket_path should be correctly configured",
			input: func(c *Config) {
				c.Server.SocketPath = "/foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "/foo", c.BindLocalAddress.String())
				require.Equal(t, "unix", c.BindLocalAddress.Network())
			},
		},
		{
			msg: "log_file allows to reopen",
			input: func(c *Config) {
				c.Server.LogFile = path.Join(testDir, "foo")
			},
			test: func(t *testing.T, c *server.Config) {
				require.NotNil(t, c.Log)
				require.NotNil(t, c.LogReopener)
			},
		},
	}
}

func testParseConfigGoodOS(t *testing.T, c *Config) {
	assert.Equal(t, c.Server.SocketPath, "/tmp/spire-server/private/api-test.sock")
}

func getAvailablePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()

	addrPort, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		return "", err
	}

	return strconv.Itoa(int(addrPort.Port())), nil
}
