package memory_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
)

func TestKeyManagerContract(t *testing.T) {
	keymanagertest.Test(t, func(t *testing.T) keymanager.KeyManager {
		km := new(keymanager.V1)
		plugintest.Load(t, memory.BuiltIn(), km)
		return km
	})
}
