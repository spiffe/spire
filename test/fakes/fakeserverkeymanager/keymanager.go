package fakeserverkeymanager

import (
	"testing"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/testkey"
)

func New(t *testing.T) keymanager.KeyManager {
	keys := new(testkey.Keys)

	plugin := keyManager{
		Base: keymanagerbase.New(keymanagerbase.Funcs{
			GenerateRSA2048Key: keys.NextRSA2048,
			GenerateRSA4096Key: keys.NextRSA4096,
			GenerateEC256Key:   keys.NextEC256,
			GenerateEC384Key:   keys.NextEC384,
		}),
	}

	v1 := new(keymanager.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", keymanagerv1.KeyManagerPluginServer(plugin)), v1)
	return v1
}

type keyManager struct {
	*keymanagerbase.Base
}
