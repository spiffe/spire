package datastore

import (
	"context"
	"crypto"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// WithBundleUpdateCallback wraps a datastore interface and provides updates to
// bundle publishers in operations that modify the local bundle.
func WithBundleUpdateCallback(ds datastore.DataStore, bundleUpdated func()) datastore.DataStore {
	return datastoreWrapper{
		DataStore:     ds,
		bundleUpdated: bundleUpdated,
	}
}

type datastoreWrapper struct {
	datastore.DataStore
	bundleUpdated func()
}

func (w datastoreWrapper) AppendBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	defer w.bundleUpdated()
	return w.DataStore.AppendBundle(ctx, bundle)
}

func (w datastoreWrapper) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (_ bool, err error) {
	defer w.bundleUpdated()
	return w.DataStore.PruneBundle(ctx, trustDomainID, expiresBefore)
}

func (w datastoreWrapper) RevokeX509CA(ctx context.Context, trustDomainID string, publicKey crypto.PublicKey) (err error) {
	defer w.bundleUpdated()
	return w.DataStore.RevokeX509CA(ctx, trustDomainID, publicKey)
}

func (w datastoreWrapper) RevokeJWTKey(ctx context.Context, trustDomainID string, keyID string) (_ *common.PublicKey, err error) {
	defer w.bundleUpdated()
	return w.DataStore.RevokeJWTKey(ctx, trustDomainID, keyID)
}
