package dscache

import (
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"golang.org/x/net/context"
)

const (
	datastoreCacheExpiry = time.Second
)

type useCache struct{}

func WithCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, useCache{}, struct{}{})
}

type bundleEntry struct {
	mu   sync.Mutex
	ts   time.Time
	resp *datastore.FetchBundleResponse
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

func (ds *DatastoreCache) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	ds.bundlesMu.Lock()
	entry, ok := ds.bundles[req.TrustDomainId]
	if !ok {
		entry = &bundleEntry{}
		ds.bundles[req.TrustDomainId] = entry
	}
	ds.bundlesMu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.ts.IsZero() || ds.clock.Now().Sub(entry.ts) >= datastoreCacheExpiry || ctx.Value(useCache{}) == nil {
		resp, err := ds.DataStore.FetchBundle(ctx, req)
		if err != nil {
			return nil, err
		}
		// Don't cache bundle "misses"
		if resp.Bundle == nil {
			return resp, nil
		}
		entry.resp = resp
		entry.ts = ds.clock.Now()
	}
	return entry.resp, nil
}

func (ds *DatastoreCache) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (resp *datastore.PruneBundleResponse, err error) {
	if resp, err = ds.DataStore.PruneBundle(ctx, req); err == nil {
		ds.invalidateBundleEntry(req.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (resp *datastore.AppendBundleResponse, err error) {
	if resp, err = ds.DataStore.AppendBundle(ctx, req); err == nil {
		ds.invalidateBundleEntry(req.Bundle.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (resp *datastore.UpdateBundleResponse, err error) {
	if resp, err = ds.DataStore.UpdateBundle(ctx, req); err == nil {
		ds.invalidateBundleEntry(req.Bundle.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (resp *datastore.DeleteBundleResponse, err error) {
	if resp, err = ds.DataStore.DeleteBundle(ctx, req); err == nil {
		ds.invalidateBundleEntry(req.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (resp *datastore.SetBundleResponse, err error) {
	if resp, err = ds.DataStore.SetBundle(ctx, req); err == nil {
		ds.invalidateBundleEntry(req.Bundle.TrustDomainId)
	}
	return
}

func (ds *DatastoreCache) invalidateBundleEntry(trustDomainID string) {
	ds.bundlesMu.Lock()
	delete(ds.bundles, trustDomainID)
	ds.bundlesMu.Unlock()
}
