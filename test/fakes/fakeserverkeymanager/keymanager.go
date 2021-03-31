package fakeserverkeymanager

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/server/keymanager/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
)

func New(t *testing.T) keymanager.KeyManager {
	keys := new(testkey.Keys)

	plugin := keyManager{
		Base: keymanagerbase.New(keymanagerbase.Funcs{
			GenerateRSA1024Key: keys.NextRSA1024,
			GenerateRSA2048Key: keys.NextRSA2048,
			GenerateRSA4096Key: keys.NextRSA4096,
			GenerateEC256Key:   keys.NextEC256,
			GenerateEC384Key:   keys.NextEC384,
		}),
	}

	var km keymanager.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("fake", keymanagerv0.PluginServer(plugin)), &km)
	return km
}

type keyManager struct {
	*keymanagerbase.Base
}

func (keyManager) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (keyManager) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
