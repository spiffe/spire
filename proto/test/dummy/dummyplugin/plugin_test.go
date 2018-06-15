package main

import (
	"os/exec"
	"testing"

	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/test/dummy"
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

	client, err := go_plugin.NewClient(config).Client()
	require.NoError(err)

	raw, err := client.Dispense("dummy")
	require.NoError(err)

	plugin, ok := raw.(*dummy.GRPCClient)
	require.True(ok)

	return plugin, func() {
		require.NoError(client.Close())
	}
}
