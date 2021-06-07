package keymanager

import (
	"context"
	"crypto"

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

func (w keyManagerWrapper) Single() (keymanager.SingleKeyManager, bool) {
	km, ok := w.km.Single()
	if !ok {
		return nil, false
	}
	return singleKeyManagerWrapper{PluginInfo: w.PluginInfo, km: km, m: w.m}, true
}

func (w keyManagerWrapper) Multi() (keymanager.MultiKeyManager, bool) {
	km, ok := w.km.Multi()
	if !ok {
		return nil, false
	}
	return multiKeyManagerWrapper{PluginInfo: w.PluginInfo, km: km, m: w.m}, true
}

type singleKeyManagerWrapper struct {
	catalog.PluginInfo
	km keymanager.SingleKeyManager
	m  telemetry.Metrics
}

func (w singleKeyManagerWrapper) GenerateKey(ctx context.Context) (_ crypto.Signer, err error) {
	defer StartGenerateKeyPairCall(w.m).Done(&err)
	return w.km.GenerateKey(ctx)
}

func (w singleKeyManagerWrapper) GetKey(ctx context.Context) (_ crypto.Signer, err error) {
	defer StartFetchPrivateKeyCall(w.m).Done(&err)
	return w.km.GetKey(ctx)
}

func (w singleKeyManagerWrapper) SetKey(ctx context.Context, key crypto.Signer) (err error) {
	defer StartStorePrivateKeyCall(w.m).Done(&err)
	return w.km.SetKey(ctx, key)
}

type multiKeyManagerWrapper struct {
	catalog.PluginInfo
	km keymanager.MultiKeyManager
	m  telemetry.Metrics
}

func (w multiKeyManagerWrapper) GenerateKey(ctx context.Context, keyID string, keyType keymanager.KeyType) (_ keymanager.Key, err error) {
	defer StartGenerateKeyCall(w.m).Done(&err)
	return w.km.GenerateKey(ctx, keyID, keyType)
}

func (w multiKeyManagerWrapper) GetKey(ctx context.Context, keyID string) (_ keymanager.Key, err error) {
	defer StartGetKeyCall(w.m).Done(&err)
	return w.km.GetKey(ctx, keyID)
}

func (w multiKeyManagerWrapper) GetKeys(ctx context.Context) (_ []keymanager.Key, err error) {
	defer StartGetKeysCall(w.m).Done(&err)
	return w.km.GetKeys(ctx)
}
