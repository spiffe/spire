package node

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

type bundleEntry struct {
	mu   sync.Mutex
	ts   time.Time
	resp *datastore.FetchBundleResponse
}

type datastoreCache struct {
	datastore.DataStore
	clock clock.Clock

	bundlesMu sync.Mutex
	bundles   map[string]*bundleEntry
}

func newDatastoreCache(ds datastore.DataStore, clock clock.Clock) *datastoreCache {
	return &datastoreCache{
		DataStore: ds,
		clock:     clock,
		bundles:   make(map[string]*bundleEntry),
	}
}

func (ds *datastoreCache) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	ds.bundlesMu.Lock()
	entry, ok := ds.bundles[req.TrustDomainId]
	if !ok {
		entry = &bundleEntry{}
		ds.bundles[req.TrustDomainId] = entry
	}
	ds.bundlesMu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.ts.IsZero() || ds.clock.Now().Sub(entry.ts) >= datastoreCacheExpiry {
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
