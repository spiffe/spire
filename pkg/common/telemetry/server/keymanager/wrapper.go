package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

type serverKeyManagerWrapper struct {
	m telemetry.Metrics
	k keymanager.KeyManager
}

func WithMetrics(km keymanager.KeyManager, metrics telemetry.Metrics) keymanager.KeyManager {
	return serverKeyManagerWrapper{
		m: metrics,
		k: km,
	}
}

func (w serverKeyManagerWrapper) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (_ *keymanager.GenerateKeyResponse, err error) {
	callCounter := StartGenerateKeyCall(w.m)
	defer callCounter.Done(&err)

	ctx, cancel := context.WithTimeout(ctx, keymanager.RPCTimeout)
	defer cancel()

	return w.k.GenerateKey(ctx, req)
}

func (w serverKeyManagerWrapper) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (_ *keymanager.GetPublicKeyResponse, err error) {
	callCounter := StartGetPublicKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GetPublicKey(ctx, req)
}

func (w serverKeyManagerWrapper) GetPublicKeys(ctx context.Context, req *keymanager.GetPublicKeysRequest) (_ *keymanager.GetPublicKeysResponse, err error) {
	callCounter := StartGetPublicKeysCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GetPublicKeys(ctx, req)
}

func (w serverKeyManagerWrapper) SignData(ctx context.Context, req *keymanager.SignDataRequest) (_ *keymanager.SignDataResponse, err error) {
	callCounter := StartSignDataCall(w.m)
	defer callCounter.Done(&err)
	return w.k.SignData(ctx, req)
}
