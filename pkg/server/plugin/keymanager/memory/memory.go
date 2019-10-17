package memory

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *KeyManager) catalog.Plugin {
	return catalog.MakePlugin("memory", keymanager.PluginServer(p))
}

type KeyManager struct {
	*base.Base
}

func New() *KeyManager {
	return &KeyManager{
		Base: base.New(base.Impl{
			ErrorFn: newError,
		}),
	}
}

func (m *KeyManager) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (m *KeyManager) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func newError(format string, args ...interface{}) error {
	return fmt.Errorf("keymanager(memory): "+format, args...)
}
