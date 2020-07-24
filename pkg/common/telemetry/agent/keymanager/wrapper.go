package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type agentKeyManagerWrapper struct {
	m telemetry.Metrics
	k keymanager.KeyManager
}

func WithMetrics(km keymanager.KeyManager, metrics telemetry.Metrics) keymanager.KeyManager {
	return agentKeyManagerWrapper{
		m: metrics,
		k: km,
	}
}

func (w agentKeyManagerWrapper) GenerateKeyPair(ctx context.Context, req *keymanager.GenerateKeyPairRequest) (_ *keymanager.GenerateKeyPairResponse, err error) {
	callCounter := StartGenerateKeyPairCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GenerateKeyPair(ctx, req)
}

func (w agentKeyManagerWrapper) FetchPrivateKey(ctx context.Context, req *keymanager.FetchPrivateKeyRequest) (_ *keymanager.FetchPrivateKeyResponse, err error) {
	callCounter := StartFetchPrivateKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.FetchPrivateKey(ctx, req)
}

func (w agentKeyManagerWrapper) StorePrivateKey(ctx context.Context, req *keymanager.StorePrivateKeyRequest) (_ *keymanager.StorePrivateKeyResponse, err error) {
	callCounter := StartStorePrivateKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.StorePrivateKey(ctx, req)
}
