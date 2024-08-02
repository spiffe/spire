package dscache

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	datastoreCacheExpiry = time.Second
)

type useCache struct{}

func WithCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, useCache{}, struct{}{})
}

type bundleEntry struct {
	mu     sync.Mutex
	ts     time.Time
	bundle *common.Bundle
}

type DatastoreCache struct {
	datastore.DataStore
	clock clock.Clock

	bundlesMu sync.Mutex
	bundles   map[string]*bundleEntry
}

func New(ds datastore.DataStore, clock clock.Clock) *DatastoreCache {
	return &DatastoreCache{
		DataStore: ds,
		clock:     clock,
		bundles:   make(map[string]*bundleEntry),
	}
}

func (ds *DatastoreCache) FetchBundle(ctx context.Context, trustDomain string) (*common.Bundle, error) {
	ds.bundlesMu.Lock()
	entry, ok := ds.bundles[trustDomain]
	if !ok {
		entry = &bundleEntry{}
		ds.bundles[trustDomain] = entry
	}
	ds.bundlesMu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.ts.IsZero() || ds.clock.Now().Sub(entry.ts) >= datastoreCacheExpiry || ctx.Value(useCache{}) == nil {
		bundle, err := ds.DataStore.FetchBundle(ctx, trustDomain)
		if err != nil {
			return nil, err
		}
		// Don't cache bundle "misses"
		if bundle == nil {
			return nil, nil
		}
		entry.bundle = bundle
		entry.ts = ds.clock.Now()
	}
	return entry.bundle, nil
}

func (ds *DatastoreCache) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error) {
	if changed, err = ds.DataStore.PruneBundle(ctx, trustDomainID, expiresBefore); err == nil {
		ds.invalidateBundleEntry(trustDomainID)
	}
	return
}

func (ds *DatastoreCache) AppendBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if bundle, err = ds.DataStore.AppendBundle(ctx, b); err == nil {
		ds.invalidateBundleEntry(b.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) UpdateBundle(ctx context.Context, b *common.Bundle, mask *common.BundleMask) (bundle *common.Bundle, err error) {
	if bundle, err = ds.DataStore.UpdateBundle(ctx, b, mask); err == nil {
		ds.invalidateBundleEntry(b.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) DeleteBundle(ctx context.Context, td string, mode datastore.DeleteMode) (err error) {
	if err = ds.DataStore.DeleteBundle(ctx, td, mode); err == nil {
		ds.invalidateBundleEntry(td)
	}
	return
}

func (ds *DatastoreCache) SetBundle(ctx context.Context, b *common.Bundle) (bundle *common.Bundle, err error) {
	if bundle, err = ds.DataStore.SetBundle(ctx, b); err == nil {
		ds.invalidateBundleEntry(b.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) (err error) {
	if err = ds.DataStore.TaintX509CA(ctx, trustDomainID, subjectKeyIDToTaint); err == nil {
		ds.invalidateBundleEntry(trustDomainID)
	}
	return
}

func (ds *DatastoreCache) RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) (err error) {
	if err = ds.DataStore.RevokeX509CA(ctx, trustDomainID, subjectKeyIDToRevoke); err == nil {
		ds.invalidateBundleEntry(trustDomainID)
	}
	return
}

func (ds *DatastoreCache) TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (taintedKey *common.PublicKey, err error) {
	if taintedKey, err = ds.DataStore.TaintJWTKey(ctx, trustDomainID, authorityID); err == nil {
		ds.invalidateBundleEntry(trustDomainID)
	}
	return
}

func (ds *DatastoreCache) RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (revokedKey *common.PublicKey, err error) {
	if revokedKey, err = ds.DataStore.RevokeJWTKey(ctx, trustDomainID, authorityID); err == nil {
		ds.invalidateBundleEntry(trustDomainID)
	}
	return
}

func (ds *DatastoreCache) invalidateBundleEntry(trustDomainID string) {
	ds.bundlesMu.Lock()
	delete(ds.bundles, trustDomainID)
	ds.bundlesMu.Unlock()
}
