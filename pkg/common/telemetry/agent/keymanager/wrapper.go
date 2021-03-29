package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
)

type agentKeyManagerWrapper struct {
	m telemetry.Metrics
	k keymanagerv0.KeyManager
}

func WithMetrics(km keymanagerv0.KeyManager, metrics telemetry.Metrics) keymanagerv0.KeyManager {
	return agentKeyManagerWrapper{
		m: metrics,
		k: km,
	}
}

func (w agentKeyManagerWrapper) GenerateKeyPair(ctx context.Context, req *keymanagerv0.GenerateKeyPairRequest) (_ *keymanagerv0.GenerateKeyPairResponse, err error) {
	callCounter := StartGenerateKeyPairCall(w.m)
	defer callCounter.Done(&err)
	return w.k.GenerateKeyPair(ctx, req)
}

func (w agentKeyManagerWrapper) FetchPrivateKey(ctx context.Context, req *keymanagerv0.FetchPrivateKeyRequest) (_ *keymanagerv0.FetchPrivateKeyResponse, err error) {
	callCounter := StartFetchPrivateKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.FetchPrivateKey(ctx, req)
}

func (w agentKeyManagerWrapper) StorePrivateKey(ctx context.Context, req *keymanagerv0.StorePrivateKeyRequest) (_ *keymanagerv0.StorePrivateKeyResponse, err error) {
	callCounter := StartStorePrivateKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.k.StorePrivateKey(ctx, req)
}
