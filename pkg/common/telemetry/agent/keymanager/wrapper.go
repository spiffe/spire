package keymanager

import (
	"context"
	"crypto"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type keyManagerWrapper struct {
	keymanager.KeyManager
	m telemetry.Metrics
}

func WithMetrics(km keymanager.KeyManager, metrics telemetry.Metrics) keymanager.KeyManager {
	return keyManagerWrapper{
		KeyManager: km,
		m:          metrics,
	}
}

func (w keyManagerWrapper) GenerateKey(ctx context.Context) (_ crypto.Signer, err error) {
	defer StartGenerateKeyPairCall(w.m).Done(&err)
	return w.KeyManager.GenerateKey(ctx)
}

func (w keyManagerWrapper) GetKey(ctx context.Context) (_ crypto.Signer, err error) {
	defer StartFetchPrivateKeyCall(w.m).Done(&err)
	return w.KeyManager.GetKey(ctx)
}

func (w keyManagerWrapper) SetKey(ctx context.Context, key crypto.Signer) (err error) {
	defer StartStorePrivateKeyCall(w.m).Done(&err)
	return w.KeyManager.SetKey(ctx, key)
}
