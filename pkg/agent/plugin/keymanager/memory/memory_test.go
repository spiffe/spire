package memory_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	keymanagertest "github.com/spiffe/spire/pkg/agent/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestKeyManagerContract(t *testing.T) {
	keymanagertest.Test(t, keymanagertest.Config{
		Create: func(t *testing.T) keymanager.MultiKeyManager {
			km := new(keymanager.V1)
			plugintest.Load(t, memory.BuiltIn(), km)
			multi, ok := km.Multi()
			require.True(t, ok)
			return multi
		},
	})
}
