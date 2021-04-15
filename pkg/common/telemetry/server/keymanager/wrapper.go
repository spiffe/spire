package keymanager

import (
	"context"
	"crypto"
	"io"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

func WithMetrics(km keymanager.KeyManager, metrics telemetry.Metrics) keymanager.KeyManager {
	return keyManagerWrapper{
		KeyManager: km,
		m:          metrics,
	}
}

type keyManagerWrapper struct {
	keymanager.KeyManager
	m telemetry.Metrics
}

func (w keyManagerWrapper) GenerateKey(ctx context.Context, id string, keyType keymanager.KeyType) (_ keymanager.Key, err error) {
	defer StartGenerateKeyCall(w.m).Done(&err)
	return w.KeyManager.GenerateKey(ctx, id, keyType)
}

func (w keyManagerWrapper) GetKey(ctx context.Context, id string) (_ keymanager.Key, err error) {
	defer StartGetPublicKeyCall(w.m).Done(&err)
	key, err := w.KeyManager.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	return wrapKey(w.m, key), nil
}

func (w keyManagerWrapper) GetKeys(ctx context.Context) (_ []keymanager.Key, err error) {
	defer StartGetPublicKeysCall(w.m).Done(&err)
	keys, err := w.KeyManager.GetKeys(ctx)
	if err != nil {
		return nil, err
	}
	return wrapKeys(w.m, keys), nil
}

type keyWrapper struct {
	keymanager.Key
	m telemetry.Metrics
}

func (w keyWrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (_ []byte, err error) {
	defer StartSignDataCall(w.m).Done(&err)
	return w.Key.Sign(rand, digest, opts)
}

func wrapKeys(m telemetry.Metrics, keys []keymanager.Key) []keymanager.Key {
	if keys == nil {
		return nil
	}
	wrapped := make([]keymanager.Key, 0, len(keys))
	for _, key := range keys {
		wrapped = append(wrapped, wrapKey(m, key))
	}
	return wrapped
}

func wrapKey(m telemetry.Metrics, key keymanager.Key) keymanager.Key {
	return keyWrapper{
		Key: key,
		m:   m,
	}
}
