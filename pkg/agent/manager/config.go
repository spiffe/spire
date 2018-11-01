package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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
	TrustDomain      url.URL
	Log              logrus.FieldLogger
	Tel              telemetry.Sink
	ServerAddr       string
	SVIDCachePath    string
	BundleCachePath  string
	SyncInterval     time.Duration
	RotationInterval time.Duration
}

// New creates a cache manager based on c's configuration
func New(c *Config) (*manager, error) {
	spiffeID, err := getSpiffeIDFromSVID(c.SVID[0])
	if err != nil {
		return nil, fmt.Errorf("cannot get spiffe id from SVID: %v", err)
	}

	if c.SyncInterval == 0 {
		c.SyncInterval = 5 * time.Second
	}

	if c.RotationInterval == 0 {
		c.RotationInterval = 60 * time.Second
	}

	cache := cache.New(c.Log, c.TrustDomain.String(), c.Bundle)

	rotCfg := &svid.RotatorConfig{
		Catalog:      c.Catalog,
		Log:          c.Log,
		SVID:         c.SVID,
		SVIDKey:      c.SVIDKey,
		SpiffeID:     spiffeID,
		BundleStream: cache.SubscribeToBundleChanges(),
		ServerAddr:   c.ServerAddr,
		TrustDomain:  c.TrustDomain,
		Interval:     c.RotationInterval,
	}
	svidRotator, client := svid.NewRotator(rotCfg)

	m := &manager{
		cache:           cache,
		c:               c,
		mtx:             new(sync.RWMutex),
		svid:            svidRotator,
		spiffeID:        spiffeID,
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
		client:          client,
	}

	return m, nil
}
