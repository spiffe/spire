package nodecache

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	rebuildInterval = 5 * time.Second
)

type Cache struct {
	log              logrus.FieldLogger
	ds               datastore.DataStore
	clk              clock.Clock
	automaticRefresh bool
	enableCache      bool
	buildTime        time.Time
	mtx              sync.RWMutex
	nodes            map[string]*common.AttestedNode
	nodeRefreshTime  map[string]time.Time
}

func New(ctx context.Context, log logrus.FieldLogger, ds datastore.DataStore, clk clock.Clock, automaticRefresh, enableCache bool) (*Cache, error) {
	cache := &Cache{
		log:              log,
		ds:               ds,
		clk:              clk,
		automaticRefresh: automaticRefresh,
		enableCache:      enableCache,
		nodes:            make(map[string]*common.AttestedNode),
		nodeRefreshTime:  make(map[string]time.Time),
	}

	err := cache.Rebuild(ctx)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

func (c *Cache) LookupAttestedNode(id string) (*common.AttestedNode, time.Time) {
	if !c.enableCache {
		return nil, time.Time{}
	}

	c.mtx.RLock()
	defer c.mtx.RUnlock()

	node, ok := c.nodes[id]
	if !ok {
		return nil, time.Time{}
	}

	nodeRefreshTime, ok := c.nodeRefreshTime[id]
	if !ok {
		nodeRefreshTime = c.buildTime
	}

	return node, nodeRefreshTime
}

func (c *Cache) FetchAttestedNode(ctx context.Context, id string) (*common.AttestedNode, error) {
	node, err := c.ds.FetchAttestedNode(ctx, id)
	if err != nil {
		c.RemoveAttestedNode(id)
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.nodes[id] = node
	c.nodeRefreshTime[id] = c.clk.Now()
	return node, nil
}

func (c *Cache) Rebuild(ctx context.Context) error {
	if !c.enableCache {
		return nil
	}

	if !c.automaticRefresh {
		return nil
	}

	buildTime := c.clk.Now()
	resp, err := c.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		ValidAt: buildTime,
	})
	if err != nil {
		return err
	}

	nodes := make(map[string]*common.AttestedNode)
	for _, node := range resp.Nodes {
		nodeID := node.SpiffeId
		nodes[nodeID] = node
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.buildTime = buildTime
	c.nodes = nodes
	c.nodeRefreshTime = make(map[string]time.Time)

	return nil
}

func (c *Cache) UpdateAttestedNode(node *common.AttestedNode) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.nodes[node.SpiffeId] = node
	delete(c.nodeRefreshTime, node.SpiffeId)
	c.buildTime = c.clk.Now()
}

func (c *Cache) RemoveAttestedNode(spiffeId string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	delete(c.nodes, spiffeId)
	delete(c.nodeRefreshTime, spiffeId)
}

func (c *Cache) PeriodicRebuild(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.clk.Tick(rebuildInterval):
		if err := c.Rebuild(ctx); err != nil {
			c.log.WithError(err).Error("Fail to rebuild the attested node cache")
		}
	}

	return nil
}
