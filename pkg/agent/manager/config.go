package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/telemetry"

	tomb "gopkg.in/tomb.v2"
)

// Config holds a cache manager configuration
type Config struct {
	// Agent SVID and key resulting from successful attestation.
	SVID            *x509.Certificate
	SVIDKey         *ecdsa.PrivateKey
	Bundle          []*x509.Certificate // Initial CA bundle
	Catalog         catalog.Catalog
	TrustDomain     url.URL
	Log             logrus.FieldLogger
	Tel             telemetry.Sink
	ServerAddr      net.Addr
	SVIDCachePath   string
	BundleCachePath string
}

// New creates a cache manager based on c's configuration
func New(c *Config) (*manager, error) {
	spiffeID, err := getSpiffeIDFromSVID(c.SVID)
	if err != nil {
		return nil, fmt.Errorf("cannot get spiffe id from SVID: %v", err)
	}

	cache := cache.New(c.Log, c.Bundle)

	rotCfg := &svid.RotatorConfig{
		Log:          c.Log,
		SVID:         c.SVID,
		SVIDKey:      c.SVIDKey,
		SpiffeID:     spiffeID,
		BundleStream: cache.BundleSubscribe(),
		ServerAddr:   c.ServerAddr,
		TrustDomain:  c.TrustDomain,
	}
	svidRotator, client := svid.NewRotator(rotCfg)

	m := &manager{
		cache:           cache,
		c:               c,
		t:               new(tomb.Tomb),
		mtx:             new(sync.RWMutex),
		svid:            svidRotator,
		spiffeID:        spiffeID,
		serverSPIFFEID:  "spiffe://" + c.TrustDomain.Host + "/spiffe/server",
		serverAddr:      c.ServerAddr,
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
		syncFreq:        5 * time.Second,
	}

	err = m.addClient(client, m.spiffeID, m.serverSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("cannot create sync client: %v", err)
	}

	return m, nil
}
