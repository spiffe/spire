package memory

import (
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
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
