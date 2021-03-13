package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/server/keymanager/v0"
)

type serverKeyManagerWrapper struct {
	m telemetry.Metrics
	k keymanagerv0.KeyManager
}

func WithMetrics(km keymanagerv0.KeyManager, metrics telemetry.Metrics) keymanagerv0.KeyManager {
	return serverKeyManagerWrapper{
		m: metrics,
		k: km,
	}
}

func (w serverKeyManagerWrapper) GenerateKey(ctx context.Context, req *keymanagerv0.GenerateKeyRequest) (_ *keymanagerv0.GenerateKeyResponse, err error) {
	callCounter := StartGenerateKeyCall(w.m)
	defer callCounter.Done(&err)

	return w.k.GenerateKey(ctx, req)
}

func (w serverKeyManagerWrapper) GetPublicKey(ctx context.Context, req *keymanagerv0.GetPublicKeyRequest) (_ *keymanagerv0.GetPublicKeyResponse, err error) {
	callCounter := StartGetPublicKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GetPublicKey(ctx, req)
}

func (w serverKeyManagerWrapper) GetPublicKeys(ctx context.Context, req *keymanagerv0.GetPublicKeysRequest) (_ *keymanagerv0.GetPublicKeysResponse, err error) {
	callCounter := StartGetPublicKeysCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GetPublicKeys(ctx, req)
}

func (w serverKeyManagerWrapper) SignData(ctx context.Context, req *keymanagerv0.SignDataRequest) (_ *keymanagerv0.SignDataResponse, err error) {
	callCounter := StartSignDataCall(w.m)
	defer callCounter.Done(&err)
	return w.k.SignData(ctx, req)
}
