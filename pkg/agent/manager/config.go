package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Config holds a cache manager configuration
type Config struct {
	// Agent SVID and key resulting from successful attestation.
	SVID             []*x509.Certificate
	SVIDKey          *ecdsa.PrivateKey
	Bundle           *cache.Bundle
	Catalog          catalog.Catalog
	TrustDomain      spiffeid.TrustDomain
	Log              logrus.FieldLogger
	Metrics          telemetry.Metrics
	ServerAddr       string
	SVIDCachePath    string
	BundleCachePath  string
	SyncInterval     time.Duration
	RotationInterval time.Duration

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

	cache := cache.New(c.Log.WithField(telemetry.SubsystemName, telemetry.CacheManager), c.TrustDomain, c.Bundle, c.Metrics)

	rotCfg := &svid.RotatorConfig{
		Catalog:      c.Catalog,
		Log:          c.Log,
		Metrics:      c.Metrics,
		SVID:         c.SVID,
		SVIDKey:      c.SVIDKey,
		BundleStream: cache.SubscribeToBundleChanges(),
		ServerAddr:   c.ServerAddr,
		TrustDomain:  c.TrustDomain,
		Interval:     c.RotationInterval,
		Clk:          c.Clk,
	}
	svidRotator, client := svid.NewRotator(rotCfg)

	m := &manager{
		cache:           cache,
		c:               c,
		mtx:             new(sync.RWMutex),
		svid:            svidRotator,
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
		client:          client,
		clk:             c.Clk,
	}

	return m
}
