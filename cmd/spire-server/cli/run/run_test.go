package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/server_good.conf")
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.BindPort, 8081)
	assert.Equal(t, c.BindHTTPPort, 8080)
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.PluginDir, "conf/server/plugin")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.BaseSVIDTtl, 999999)
	assert.Equal(t, c.ServerSVIDTtl, 999999)
	assert.Equal(t, c.Umask, "")
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags([]string{
		"-bindAddress=127.0.0.1",
		"-bindHTTPPort=8080",
		"-trustDomain=example.org",
		"-pluginDir=conf/server/plugin",
		"-logLevel=INFO",
		"-baseSVIDTtl=999999",
		"-serverSVIDTtl=999999",
		"-umask=",
	})
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.BindHTTPPort, 8080)
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.PluginDir, "conf/server/plugin")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.BaseSVIDTtl, 999999)
	assert.Equal(t, c.ServerSVIDTtl, 999999)
	assert.Equal(t, c.Umask, "")
}

func TestMergeConfigGood(t *testing.T) {
	c := &RunConfig{
		BindAddress:   "127.0.0.1",
		BindPort:      8081,
		BindHTTPPort:  8080,
		TrustDomain:   "example.org",
		PluginDir:     "conf/server/plugin",
		LogLevel:      "INFO",
		BaseSVIDTtl:   999999,
		ServerSVIDTtl: 999999,
		Umask:         "",
	}
	orig := newDefaultConfig()
	err := mergeConfig(orig, c)
	require.NoError(t, err)
	assert.Equal(t, orig.BindAddress.IP.String(), "127.0.0.1")
	assert.Equal(t, orig.BindHTTPAddress.IP.String(), "127.0.0.1")
	assert.Equal(t, orig.BindAddress.Port, 8081)
	assert.Equal(t, orig.BindHTTPAddress.Port, 8080)
	assert.Equal(t, orig.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, orig.TrustDomain.Host, "example.org")
	assert.Equal(t, orig.PluginDir, "conf/server/plugin")
	assert.Equal(t, orig.Umask, 0077)
}
