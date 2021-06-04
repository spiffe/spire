package keymanager

import (
	"context"
	"crypto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SVIDKeyManager is a wrapper around the key manager specifically used for
// managing the agent SVID. This is more or less a short term shim until we
// can remove support for the v0 plugins and no longer have to adapt SVID
// storage to both the "single" and "multi" key manager.
type SVIDKeyManager interface {
	GenerateKey(ctx context.Context, currentKey Key) (Key, error)
	GetKeys(ctx context.Context) ([]Key, error)
	SetKey(ctx context.Context, key Key) error
}

func ForSVID(km KeyManager) SVIDKeyManager {
	if km, ok := km.Single(); ok {
		return singleSVIDKeyManager{km: km}
	}
	if km, ok := km.Multi(); ok {
		return multiSVIDKeyManager{km: km}
	}
	return unsupportedSVIDKeyManager{}
}

type singleSVIDKeyManager struct {
	km SingleKeyManager
}

func (s singleSVIDKeyManager) GenerateKey(ctx context.Context, _ Key) (Key, error) {
	key, err := s.km.GenerateKey(ctx)
	if err != nil {
		return nil, err
	}
	return signerKey{Signer: key}, nil
}

func (s singleSVIDKeyManager) GetKeys(ctx context.Context) ([]Key, error) {
	key, err := s.km.GetKey(ctx)
	switch status.Code(err) {
	case codes.OK:
		return []Key{signerKey{Signer: key}}, nil
	case codes.NotFound:
		return nil, nil
	default:
		return nil, err
	}
}

func (s singleSVIDKeyManager) SetKey(ctx context.Context, key Key) error {
	signer, ok := key.(signerKey)
	if !ok {
		return status.Errorf(codes.Internal, "key to set was not provided by this key manager")
	}
	return s.km.SetKey(ctx, signer.Signer)
}

type multiSVIDKeyManager struct {
	km MultiKeyManager
}

func (s multiSVIDKeyManager) GenerateKey(ctx context.Context, currentKey Key) (Key, error) {
	keyID := "agent-svid-A"
	if currentKey != nil && currentKey.ID() == keyID {
		keyID = "agent-svid-B"
	}
	return s.km.GenerateKey(ctx, keyID, ECP256)
}

func (s multiSVIDKeyManager) GetKeys(ctx context.Context) ([]Key, error) {
	return s.km.GetKeys(ctx)
}

func (s multiSVIDKeyManager) SetKey(ctx context.Context, key Key) error {
	// Purposefully empty. The keymanager already persists all keys it manages.
	return nil
}

type unsupportedSVIDKeyManager struct{}

func (unsupportedSVIDKeyManager) GenerateKey(ctx context.Context, currentKey Key) (Key, error) {
	return nil, status.Error(codes.Internal, "key manager does not support either the single or multi key interface")
}
func (unsupportedSVIDKeyManager) GetKeys(ctx context.Context) ([]Key, error) {
	return nil, status.Error(codes.Internal, "key manager does not support either the single or multi key interface")
}
func (unsupportedSVIDKeyManager) SetKey(ctx context.Context, key Key) error {
	return status.Error(codes.Internal, "key manager does not support either the single or multi key interface")
}

type signerKey struct{ crypto.Signer }

func (signerKey) ID() string { return "" }
