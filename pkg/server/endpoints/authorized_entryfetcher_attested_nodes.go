package endpoints

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
)

type attestedNodes struct {
	cache     *authorizedentries.Cache
	nodeCache *nodecache.Cache
	clk       clock.Clock
	ds        datastore.DataStore
	log       logrus.FieldLogger
	metrics   telemetry.Metrics

	eventTimeout time.Duration
	pageSize     int32

	fetchNodes map[string]struct{}

	// metrics change detection
	pendingNodeEvents int
	skippedNodeEvents int
	lastCacheStats    authorizedentries.CacheStats
}

func (a *attestedNodes) captureChangedNodes(ctx context.Context) error {
	resp, err := a.ds.FetchAttestedNodeChanges(ctx, &datastore.FetchAttestedNodeChangesRequest{
		EventTimeout: a.eventTimeout,
	})
	if err != nil {
		return err
	}

	for _, spiffeID := range resp.SpiffeIDs {
		a.fetchNodes[spiffeID] = struct{}{}
	}
	a.pendingNodeEvents = int(resp.PendingEvents)
	return nil
}

func (a *attestedNodes) loadCache(ctx context.Context, cache *authorizedentries.Cache) error {
	// TODO: determine if this needs paging
	nodesResp, err := a.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		FetchSelectors: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list attested nodes: %w", err)
	}

	for _, node := range nodesResp.Nodes {
		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(a.clk.Now()) {
			continue
		}
		cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
		a.nodeCache.UpdateAttestedNode(node)
	}

	return nil
}

// buildAttestedNodesCache fetches all attested nodes and adds the unexpired ones to the cache.
// It runs once at startup.
func buildAttestedNodesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, nodeCache *nodecache.Cache, pageSize int32, eventTimeout time.Duration) (*attestedNodes, error) {
	if pageSize <= 0 {
		return nil, fmt.Errorf("page size must be positive, got %d", pageSize)
	}

	attestedNodes := &attestedNodes{
		cache:        cache,
		nodeCache:    nodeCache,
		clk:          clk,
		ds:           ds,
		log:          log,
		metrics:      metrics,
		eventTimeout: eventTimeout,
		pageSize:     pageSize,

		fetchNodes: make(map[string]struct{}),

		// initialize gauges to nonsense values to force a change.
		skippedNodeEvents: -1,
		lastCacheStats: authorizedentries.CacheStats{
			AgentsByID:        -1,
			AgentsByExpiresAt: -1,
		},
	}

	if err := attestedNodes.captureChangedNodes(ctx); err != nil {
		return nil, err
	}

	if err := attestedNodes.loadCache(ctx, cache); err != nil {
		return nil, err
	}

	attestedNodes.emitMetrics()

	return attestedNodes, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *attestedNodes) updateCache(ctx context.Context) error {
	if err := a.captureChangedNodes(ctx); err != nil {
		return err
	}
	if err := a.updateCachedNodes(ctx); err != nil {
		return err
	}
	a.emitMetrics()

	return nil
}

func (a *attestedNodes) updateCachedNodes(ctx context.Context) error {
	spiffeIds := slices.Collect(maps.Keys(a.fetchNodes))
	for pageStart := 0; pageStart < len(spiffeIds); pageStart += int(a.pageSize) {
		fetchNodes := a.fetchNodesPage(spiffeIds, pageStart)
		nodes, err := a.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{BySpiffeIDs: fetchNodes, FetchSelectors: true})
		if err != nil {
			return err
		}
		seen := make(map[string]struct{}, len(nodes.Nodes))
		for _, node := range nodes.Nodes {
			agentExpiresAt := time.Unix(node.CertNotAfter, 0)
			a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
			a.nodeCache.UpdateAttestedNode(node)
			delete(a.fetchNodes, node.SpiffeId)
			seen[node.SpiffeId] = struct{}{}
		}
		for _, spiffeId := range fetchNodes {
			_, ok := seen[spiffeId]
			if !ok {
				// Node was deleted (absent from the response)
				a.nodeCache.RemoveAttestedNode(spiffeId)
				a.cache.RemoveAgent(spiffeId)
				delete(a.fetchNodes, spiffeId)
				continue
			}
		}
	}
	return nil
}

// fetchNodesPage gets the range for the page starting at pageStart
func (a *attestedNodes) fetchNodesPage(spiffeIds []string, pageStart int) []string {
	pageEnd := min(len(spiffeIds), pageStart+int(a.pageSize))
	return spiffeIds[pageStart:pageEnd]
}

func (a *attestedNodes) swapCache(cache *authorizedentries.Cache) {
	a.cache = cache
}

func (a *attestedNodes) emitMetrics() {
	if a.skippedNodeEvents != a.pendingNodeEvents {
		a.skippedNodeEvents = a.pendingNodeEvents
		server_telemetry.SetSkippedNodeEventIDsCacheCountGauge(a.metrics, a.skippedNodeEvents)
	}

	cacheStats := a.cache.Stats()
	// AgentsByID and AgentsByExpiresAt should be the same.
	if a.lastCacheStats.AgentsByID != cacheStats.AgentsByID {
		a.lastCacheStats.AgentsByID = cacheStats.AgentsByID
		server_telemetry.SetAgentsByIDCacheCountGauge(a.metrics, a.lastCacheStats.AgentsByID)
	}
	if a.lastCacheStats.AgentsByExpiresAt != cacheStats.AgentsByExpiresAt {
		a.lastCacheStats.AgentsByExpiresAt = cacheStats.AgentsByExpiresAt
		server_telemetry.SetAgentsByExpiresAtCacheCountGauge(a.metrics, a.lastCacheStats.AgentsByExpiresAt)
	}
}
