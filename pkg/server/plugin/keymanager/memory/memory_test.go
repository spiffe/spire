package memory_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
)

func init() {
	keymanagerbase.RandSource = rand.New(rand.NewSource(time.Now().Unix()))
}

func TestKeyManagerContract(t *testing.T) {
	keymanagertest.Test(t, keymanagertest.Config{
		Create: func(t *testing.T) keymanager.KeyManager {
			km := new(keymanager.V1)
			plugintest.Load(t, memory.BuiltIn(), km)
			return km
		},
	})
}
