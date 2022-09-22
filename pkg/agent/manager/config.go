package manager

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	managerCache "github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Config holds a cache manager configuration
type Config struct {
	// Agent SVID and key resulting from successful attestation.
	SVID             []*x509.Certificate
	SVIDKey          keymanager.Key
	Bundle           *managerCache.Bundle
	Reattestable     bool
	Catalog          catalog.Catalog
	TrustDomain      spiffeid.TrustDomain
	Log              logrus.FieldLogger
	Metrics          telemetry.Metrics
	ServerAddr       string
	Storage          storage.Storage
	WorkloadKeyType  workloadkey.KeyType
	SyncInterval     time.Duration
	RotationInterval time.Duration
	SVIDStoreCache   *storecache.Cache
	SVIDCacheMaxSize int
	NodeAttestor     nodeattestor.NodeAttestor

	// Clk is the clock the manager will use to get time
	Clk clock.Clock
}

// New creates a cache manager based on c's configuration
func New(c *Config) Manager {
	return newManager(c)
}

func newManager(c *Config) *manager {
	if c.SyncInterval == 0 {
		c.SyncInterval = 5 * time.Second
	}

	if c.RotationInterval == 0 {
		c.RotationInterval = svid.DefaultRotatorInterval
	}

	if c.Clk == nil {
		c.Clk = clock.New()
	}

	var cache Cache
	if c.SVIDCacheMaxSize > 0 {
		// use LRU cache implementation
		cache = managerCache.NewLRUCache(c.Log.WithField(telemetry.SubsystemName, telemetry.CacheManager), c.TrustDomain, c.Bundle,
			c.Metrics, c.SVIDCacheMaxSize, c.Clk)
	} else {
		cache = managerCache.New(c.Log.WithField(telemetry.SubsystemName, telemetry.CacheManager), c.TrustDomain, c.Bundle,
			c.Metrics)
	}

	rotCfg := &svid.RotatorConfig{
		SVIDKeyManager: keymanager.ForSVID(c.Catalog.GetKeyManager()),
		Log:            c.Log,
		Metrics:        c.Metrics,
		SVID:           c.SVID,
		SVIDKey:        c.SVIDKey,
		BundleStream:   cache.SubscribeToBundleChanges(),
		ServerAddr:     c.ServerAddr,
		TrustDomain:    c.TrustDomain,
		Interval:       c.RotationInterval,
		Clk:            c.Clk,
		NodeAttestor:   c.NodeAttestor,
		Reattestable:   c.Reattestable,
	}
	svidRotator, client := svid.NewRotator(rotCfg)

	m := &manager{
		cache:          cache,
		c:              c,
		mtx:            new(sync.RWMutex),
		svid:           svidRotator,
		storage:        c.Storage,
		client:         client,
		clk:            c.Clk,
		svidStoreCache: c.SVIDStoreCache,
	}

	return m
}
