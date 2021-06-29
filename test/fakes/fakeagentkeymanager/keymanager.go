package fakeagentkeymanager

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/test/plugintest"
)

// New returns a fake key manager
func New(t *testing.T, dir string) keymanager.KeyManager {
	km := new(keymanager.V1)
	if dir != "" {
		plugintest.Load(t, disk.BuiltIn(), km, plugintest.Configuref("directory = %q", dir))
	} else {
		plugintest.Load(t, memory.BuiltIn(), km)
	}
	return km
}
