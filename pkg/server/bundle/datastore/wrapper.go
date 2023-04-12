package datastore

import (
	"context"
	"crypto"
	"time"

	"github.com/spiffe/spire/pkg/server/bundle/pubmanager"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// WithBundlePublisher wraps a datastore interface and provides updates to
// bundle publishers in operations that modify the local bundle.
func WithBundlePublisher(ds datastore.DataStore, pubManager *pubmanager.Manager) datastore.DataStore {
	return datastoreWrapper{
		DataStore:  ds,
		pubmanager: pubManager,
	}
}

type datastoreWrapper struct {
	datastore.DataStore
	pubmanager *pubmanager.Manager
}

func (w datastoreWrapper) AppendBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	defer w.pubmanager.BundleUpdated()
	return w.DataStore.AppendBundle(ctx, bundle)
}

func (w datastoreWrapper) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (_ bool, err error) {
	defer w.pubmanager.BundleUpdated()
	return w.DataStore.PruneBundle(ctx, trustDomainID, expiresBefore)
}

func (w datastoreWrapper) RevokeX509CA(ctx context.Context, trustDomainID string, publicKey crypto.PublicKey) (err error) {
	defer w.pubmanager.BundleUpdated()
	return w.DataStore.RevokeX509CA(ctx, trustDomainID, publicKey)
}

func (w datastoreWrapper) RevokeJWTKey(ctx context.Context, trustDomainID string, keyID string) (_ *common.PublicKey, err error) {
	defer w.pubmanager.BundleUpdated()
	return w.DataStore.RevokeJWTKey(ctx, trustDomainID, keyID)
}

func (w datastoreWrapper) UpdateBundle(ctx context.Context, bundle *common.Bundle, mask *common.BundleMask) (_ *common.Bundle, err error) {
	defer w.pubmanager.BundleUpdated()
	return w.DataStore.UpdateBundle(ctx, bundle, mask)
}
