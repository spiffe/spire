package endpoints

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type entryCacheBuilderFn func(ctx context.Context) (entrycache.Cache, error)
type entryCacheUpdateFn func(ctx context.Context, cache entrycache.Cache) error

type AuthorizedEntryFetcherWithFullCache struct {
	updateCache         entryCacheUpdateFn
	cache               entrycache.Cache
	clk                 clock.Clock
	log                 logrus.FieldLogger
	mu                  sync.RWMutex
	cacheReloadInterval time.Duration
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, buildCache entryCacheBuilderFn, updateCache entryCacheUpdateFn, log logrus.FieldLogger, clk clock.Clock, cacheReloadInterval time.Duration) (*AuthorizedEntryFetcherWithFullCache, error) {
	log.Info("Building in-memory entry cache")
	cache, err := buildCache(ctx)
	if err != nil {
		return nil, err
	}

	log.Info("Completed building in-memory entry cache")
	return &AuthorizedEntryFetcherWithFullCache{
		updateCache:         updateCache,
		cache:               cache,
		clk:                 clk,
		log:                 log,
		cacheReloadInterval: cacheReloadInterval,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.GetAuthorizedEntries(agentID), nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAllCachedEntries() ([]*types.Entry, error) {
	return a.cache.GetAllEntries(), nil
}

// RunRebuildCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	rebuild := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.log.Info("Updating Cache")
		err := a.updateCache(ctx, a.cache)
		if err != nil {
			a.log.WithError(err).Error("Failed to reload entry cache")
		}

		entries, err := a.FetchAllCachedEntries()
		if err != nil {
			a.log.WithError(err).Error("Failed to get cache")
			return 
		}
		for _, entry := range entries {
			printEntry(entry)
		}
	}

	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-a.clk.After(a.cacheReloadInterval):
			rebuild()
		}
	}
}

func printEntry(e *types.Entry) {
	fmt.Printf("Entry ID         : %s\n", printableEntryID(e.Id))
	fmt.Printf("SPIFFE ID        : %s\n", protoToIDString(e.SpiffeId))
	fmt.Printf("Parent ID        : %s\n", protoToIDString(e.ParentId))
	fmt.Printf("Revision         : %d\n", e.RevisionNumber)
	fmt.Printf("\n")
}

func printableEntryID(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
}

// protoToIDString converts a SPIFFE ID from the given *types.SPIFFEID to string
func protoToIDString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
