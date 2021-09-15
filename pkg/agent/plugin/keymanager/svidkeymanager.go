package keymanager

import (
	"context"
)

// SVIDKeyManager is a wrapper around the key manager specifically used for
// managing the agent SVID. This is more or less a short term shim until we
// can remove support for the v0 plugins and no longer have to adapt SVID
// storage to both the "single" and "multi" key manager.
type SVIDKeyManager interface {
	GenerateKey(ctx context.Context, currentKey Key) (Key, error)
	GetKeys(ctx context.Context) ([]Key, error)
}

func ForSVID(km KeyManager) SVIDKeyManager {
	return svidKeyManager{km: km}
}

type svidKeyManager struct {
	km KeyManager
}

func (s svidKeyManager) GenerateKey(ctx context.Context, currentKey Key) (Key, error) {
	keyID := "agent-svid-A"
	if currentKey != nil && currentKey.ID() == keyID {
		keyID = "agent-svid-B"
	}
	return s.km.GenerateKey(ctx, keyID, ECP256)
}

func (s svidKeyManager) GetKeys(ctx context.Context) ([]Key, error) {
	return s.km.GetKeys(ctx)
}
