package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

func WithMetrics(km keymanager.KeyManager, metrics telemetry.Metrics) keymanager.KeyManager {
	return keyManagerWrapper{
		PluginInfo: km,
		km:         km,
		m:          metrics,
	}
}

type keyManagerWrapper struct {
	catalog.PluginInfo
	km keymanager.KeyManager
	m  telemetry.Metrics
}

func (w keyManagerWrapper) GenerateKey(ctx context.Context, keyID string, keyType keymanager.KeyType) (_ keymanager.Key, err error) {
	defer StartGenerateKeyCall(w.m).Done(&err)
	return w.km.GenerateKey(ctx, keyID, keyType)
}

func (w keyManagerWrapper) GetKey(ctx context.Context, keyID string) (_ keymanager.Key, err error) {
	defer StartGetKeyCall(w.m).Done(&err)
	return w.km.GetKey(ctx, keyID)
}

func (w keyManagerWrapper) GetKeys(ctx context.Context) (_ []keymanager.Key, err error) {
	defer StartGetKeysCall(w.m).Done(&err)
	return w.km.GetKeys(ctx)
}
