package endpoints

import (
	"context"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type attestedNodes struct {
	cache   *authorizedentries.Cache
	clk     clock.Clock
	ds      datastore.DataStore
	log     logrus.FieldLogger
	metrics telemetry.Metrics

	eventsBeforeFirst map[uint]struct{}

	firstEvent     uint
	firstEventTime time.Time
	lastEvent      uint

	eventTracker          *eventTracker
	sqlTransactionTimeout time.Duration

	fetchNodes map[string]struct{}

	// metrics change detection
	skippedNodeEvents int
	lastCacheStats    authorizedentries.CacheStats
}

func (a *attestedNodes) captureChangedNodes(ctx context.Context) error {
	if err := a.searchBeforeFirstEvent(ctx); err != nil {
		return err
	}
	a.selectPolledEvents(ctx)
	if err := a.scanForNewEvents(ctx); err != nil {
		return err
	}

	return nil
}

func (a *attestedNodes) searchBeforeFirstEvent(ctx context.Context) error {
	// First event detected, and startup was less than a transaction timout away.
	if !a.firstEventTime.IsZero() && a.clk.Now().Sub(a.firstEventTime) <= a.sqlTransactionTimeout {
		resp, err := a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
			LessThanEventID: a.firstEvent,
		})
		if err != nil {
			return err
		}
		for _, event := range resp.Events {
			// if we have seen it before, don't reload it.
			if _, seen := a.eventsBeforeFirst[event.EventID]; !seen {
				a.fetchNodes[event.SpiffeID] = struct{}{}
				a.eventsBeforeFirst[event.EventID] = struct{}{}
			}
		}
		return nil
	}

	// zero out unused event tracker
	if len(a.eventsBeforeFirst) != 0 {
		a.eventsBeforeFirst = make(map[uint]struct{})
	}

	return nil
}

func (a *attestedNodes) selectPolledEvents(ctx context.Context) {
	// check if the polled events have appeared out-of-order
	selectedEvents := a.eventTracker.SelectEvents()
	for _, eventID := range selectedEvents {
		log := a.log.WithField(telemetry.EventID, eventID)
		event, err := a.ds.FetchAttestedNodeEvent(ctx, eventID)

		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			continue
		default:
			log.WithError(err).Errorf("Failed to fetch info about skipped node event %d", eventID)
			continue
		}

		a.fetchNodes[event.SpiffeID] = struct{}{}
		a.eventTracker.StopTracking(eventID)
	}
	a.eventTracker.FreeEvents(selectedEvents)
}

func (a *attestedNodes) scanForNewEvents(ctx context.Context) error {
	// If we haven't seen an event, scan for all events; otherwise, scan from the last event.
	var resp *datastore.ListAttestedNodeEventsResponse
	var err error
	if a.firstEventTime.IsZero() {
		resp, err = a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	} else {
		resp, err = a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
			GreaterThanEventID: a.lastEvent,
		})
	}
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		// event time determines if we have seen the first event.
		if a.firstEventTime.IsZero() {
			a.firstEvent = event.EventID
			a.lastEvent = event.EventID
			a.fetchNodes[event.SpiffeID] = struct{}{}
			a.firstEventTime = a.clk.Now()
			continue
		}

		// track any skipped event ids, should they appear later.
		for skipped := a.lastEvent + 1; skipped < event.EventID; skipped++ {
			a.eventTracker.StartTracking(skipped)
		}

		// every event adds its entry to the entry fetch list.
		a.fetchNodes[event.SpiffeID] = struct{}{}
		a.lastEvent = event.EventID
	}
	return nil
}

func (a *attestedNodes) loadCache(ctx context.Context) error {
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
		a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return nil
}

// buildAttestedNodesCache fetches all attested nodes and adds the unexpired ones to the cache.
// It runs once at startup.
func buildAttestedNodesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, cacheReloadInterval, sqlTransactionTimeout time.Duration) (*attestedNodes, error) {
	pollPeriods := PollPeriods(cacheReloadInterval, sqlTransactionTimeout)

	attestedNodes := &attestedNodes{
		cache:                 cache,
		clk:                   clk,
		ds:                    ds,
		log:                   log,
		metrics:               metrics,
		sqlTransactionTimeout: sqlTransactionTimeout,

		eventsBeforeFirst: make(map[uint]struct{}),
		fetchNodes:        make(map[string]struct{}),

		eventTracker: NewEventTracker(pollPeriods),

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

	if err := attestedNodes.loadCache(ctx); err != nil {
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
	for spiffeId := range a.fetchNodes {
		node, err := a.ds.FetchAttestedNode(ctx, spiffeId)
		if err != nil {
			continue
		}

		// Node was deleted
		if node == nil {
			a.cache.RemoveAgent(spiffeId)
			delete(a.fetchNodes, spiffeId)
			continue
		}

		selectors, err := a.ds.GetNodeSelectors(ctx, spiffeId, datastore.RequireCurrent)
		if err != nil {
			continue
		}
		node.Selectors = selectors

		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
		delete(a.fetchNodes, spiffeId)
	}
	return nil
}

func (a *attestedNodes) emitMetrics() {
	if a.skippedNodeEvents != a.eventTracker.EventCount() {
		a.skippedNodeEvents = a.eventTracker.EventCount()
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
