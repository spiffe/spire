package fakeagentkeymanager

import (
	"context"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/agent/keymanager/v0"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

// New returns a fake key manager
func New(t *testing.T, dir string) keymanager.KeyManager {
	configuration := ""
	builtIn := memory.BuiltIn()
	if dir != "" {
		builtIn = disk.BuiltIn()
		configuration = fmt.Sprintf("directory = %q", dir)
	}

	// This little workaround to get at the configuration interface
	// won't be required after the catalog system refactor
	raw := struct {
		plugin.Facade
		keymanagerv0.Plugin
	}{}

	spiretest.LoadPlugin(t, builtIn, &raw)

	_, err := raw.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	require.NoError(t, err)

	return keymanager.V0{
		Facade: raw.Facade,
		Plugin: raw.Plugin,
	}
}
