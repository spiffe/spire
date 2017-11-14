package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/agent_good.conf")
	require.NoError(t, err)
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.PluginDir, "conf/agent/plugin")
	assert.Equal(t, c.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.ServerPort, 8081)
	assert.Equal(t, c.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.Umask, "")
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags([]string{
		"-dataDir=.",
		"-logLevel=INFO",
		"-pluginDir=conf/agent/plugin",
		"-serverAddress=127.0.0.1",
		"-serverPort=8081",
		"-socketPath=/tmp/agent.sock",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustDomain=example.org",
		"-umask=",
	})
	require.NoError(t, err)
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.PluginDir, "conf/agent/plugin")
	assert.Equal(t, c.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.ServerPort, 8081)
	assert.Equal(t, c.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.Umask, "")
}

func TestMergeConfigGood(t *testing.T) {
	c := &RunConfig{
		DataDir:       ".",
		LogLevel:      "INFO",
		PluginDir:     "conf/agent/plugin",
		ServerAddress: "127.0.0.1",
		ServerPort:    8081,
		SocketPath:    "/tmp/agent.sock",
		TrustDomain:   "example.org",
		Umask:         "",
	}
	orig := newDefaultConfig()
	err := mergeConfig(orig, c)
	require.NoError(t, err)
	assert.Equal(t, orig.ServerAddress.IP.String(), "127.0.0.1")
	assert.Equal(t, orig.ServerAddress.Port, 8081)
	assert.Equal(t, orig.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, orig.TrustDomain.Host, "example.org")
	assert.Equal(t, orig.PluginDir, "conf/agent/plugin")
	assert.Equal(t, orig.DataDir, ".")
	assert.Equal(t, orig.Umask, 0077)
}
