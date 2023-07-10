package endpoints

import (
	"context"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type AuthorizedEntryFetcherWithFullCache struct {
	cache                    entrycache.Cache
	clk                      clock.Clock
	log                      logrus.FieldLogger
	dataStore                datastore.DataStore
	cacheReloadInterval      time.Duration
	entryEventsPruneInterval time.Duration
}

func NewAuthorizedEntryFetcherWithFullCache(c Config, cache entrycache.Cache) (*AuthorizedEntryFetcherWithFullCache, error) {
	return &AuthorizedEntryFetcherWithFullCache{
		cache:                    cache,
		clk:                      c.Clock,
		log:                      c.Log,
		dataStore:                c.Catalog.GetDataStore(),
		cacheReloadInterval:      c.CacheReloadInterval,
		entryEventsPruneInterval: c.EntryEventsPruneInterval,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	return a.cache.GetAuthorizedEntries(agentID), nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAllCachedEntries() ([]*types.Entry, error) {
	return a.cache.GetAllEntries(), nil
}

// RunUpdateCacheTask starts a ticker which updates the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	rebuild := func() {
		if err := a.cache.Update(ctx, a.dataStore); err != nil {
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

func (a *AuthorizedEntryFetcherWithFullCache) EntryEventsPruneTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping event pruner")
			return nil
		case <-a.clk.After(a.entryEventsPruneInterval):
			a.log.Info("Pruning events")
			if err := a.pruneEntryEvents(ctx); err != nil {
				a.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherWithFullCache) pruneEntryEvents(ctx context.Context) error {
	return a.dataStore.PruneEntryEvents(ctx, a.entryEventsPruneInterval)
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
