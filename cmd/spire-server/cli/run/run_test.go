package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/server_good.conf")
	require.NoError(t, err)
	assert.Equal(t, c.Server.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Server.BindPort, 8081)
	assert.Equal(t, c.Server.BindHTTPPort, 8080)
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Umask, "")
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags([]string{
		"-bindAddress=127.0.0.1",
		"-bindHTTPPort=8080",
		"-trustDomain=example.org",
		"-logLevel=INFO",
		"-umask=",
	})
	require.NoError(t, err)
	assert.Equal(t, c.Server.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Server.BindHTTPPort, 8080)
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Umask, "")
}

func TestMergeConfigGood(t *testing.T) {
	sc := &serverConfig{
		BindAddress:  "127.0.0.1",
		BindPort:     8081,
		BindHTTPPort: 8080,
		TrustDomain:  "example.org",
		LogLevel:     "INFO",
		Umask:        "",
	}

	c := &runConfig{
		Server: *sc,
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
	assert.Equal(t, orig.Umask, 0077)
}
