package main

import (
	"os/exec"
	"testing"

	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/test/dummy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// make sure the dummyplugin binary is up to date
	if err := exec.Command("go", "build").Run(); err != nil {
		panic(err)
	}
}

func TestNoStreamPlugin(t *testing.T) {
	plugin, done := newClient(t)
	defer done()
	dummy.TestNoStream(t, plugin)
}

func TestClientStreamPlugin(t *testing.T) {
	plugin, done := newClient(t)
	defer done()
	dummy.TestClientStream(t, plugin)
}

func TestServerStreamPlugin(t *testing.T) {
	plugin, done := newClient(t)
	defer done()
	dummy.TestServerStream(t, plugin)
}

func TestBothStreamPlugin(t *testing.T) {
	plugin, done := newClient(t)
	defer done()
	dummy.TestBothStream(t, plugin)
}

func newClient(t *testing.T) (dummy.Dummy, func()) {
	require := require.New(t)

	config := &go_plugin.ClientConfig{
		HandshakeConfig: dummy.Handshake,
		Plugins: map[string]go_plugin.Plugin{
			"dummy": &dummy.GRPCPlugin{},
		},
		Cmd:              exec.Command("./dummyplugin"),
		AllowedProtocols: []go_plugin.Protocol{go_plugin.ProtocolGRPC},
		Managed:          true,
	}

	pluginClient := go_plugin.NewClient(config)

	success := false
	defer func() {
		if !success {
			pluginClient.Kill()
		}
	}()

	grpcClient, err := pluginClient.Client()
	require.NoError(err)

	defer func() {
		if !success {
			grpcClient.Close()
		}
	}()

	raw, err := grpcClient.Dispense("dummy")
	require.NoError(err, "dispensing plugin interface")

	plugin, ok := raw.(*dummy.GRPCClient)
	require.True(ok, "implements dummy.GRPCClient interface")

	success = true

	return plugin, func() {
		assert.NoError(t, grpcClient.Close())
		pluginClient.Kill()
	}
}
