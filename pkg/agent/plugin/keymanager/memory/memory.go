package memory

import (
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/common/catalog"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn("memory", keymanagerv1.KeyManagerPluginServer(p))
}

type KeyManager struct {
	*keymanagerbase.Base
}

func New() *KeyManager {
	return &KeyManager{
		Base: keymanagerbase.New(keymanagerbase.Funcs{}),
	}
}
