package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
	"google.golang.org/grpc/codes"
)

type V0 struct {
	plugin.Facade

	Plugin keymanagerv0.KeyManager
}

func (v0 V0) GenerateKey(ctx context.Context) (crypto.Signer, error) {
	resp, err := v0.Plugin.GenerateKeyPair(ctx, &keymanagerv0.GenerateKeyPairRequest{})
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	if resp.PrivateKey == nil {
		return nil, v0.Error(codes.Internal, "plugin response missing private key")
	}

	ecKey, err := x509.ParseECPrivateKey(resp.PrivateKey)
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	return ecKey, nil
}

func (v0 V0) GetKey(ctx context.Context) (crypto.Signer, error) {
	resp, err := v0.Plugin.FetchPrivateKey(ctx, &keymanagerv0.FetchPrivateKeyRequest{})
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	if resp.PrivateKey == nil {
		return nil, v0.Error(codes.NotFound, "private key not found")
	}

	ecKey, err := x509.ParseECPrivateKey(resp.PrivateKey)
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	return ecKey, nil
}

func (v0 V0) SetKey(ctx context.Context, key crypto.Signer) error {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return v0.Error(codes.Internal, "v0 key manager only supports ECDSA keys")
	}

	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return v0.Errorf(codes.Internal, "failed unexpectedly to marshal private key: %v", err)
	}

	if _, err := v0.Plugin.StorePrivateKey(context.Background(), &keymanagerv0.StorePrivateKeyRequest{
		PrivateKey: keyBytes,
	}); err != nil {
		return v0.WrapErr(err)
	}

	return nil
}
