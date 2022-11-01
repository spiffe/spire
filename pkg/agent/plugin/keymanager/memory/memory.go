package memory

import (
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type Generator = keymanagerbase.Generator

func BuiltIn() catalog.BuiltIn {
	return asBuiltIn(newKeyManager(nil))
}

func TestBuiltIn(generator Generator) catalog.BuiltIn {
	return asBuiltIn(newKeyManager(generator))
}

func asBuiltIn(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn("memory", keymanagerv1.KeyManagerPluginServer(p))
}

type KeyManager struct {
	*keymanagerbase.Base
}

func newKeyManager(generator Generator) *KeyManager {
	return &KeyManager{
		Base: keymanagerbase.New(keymanagerbase.Config{
			Generator: generator,
		}),
	}
}
