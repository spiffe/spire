package bundle

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/spire/pkg/server/datastore"
)

const (
	cacheExpiry = time.Second
)

type Cache struct {
	ds         datastore.DataStore
	bundlesMtx sync.Mutex
	bundles    map[spiffeid.TrustDomain]*bundleEntry
	clock      clock.Clock
}

func NewCache(ds datastore.DataStore, clk clock.Clock) *Cache {
	return &Cache{
		ds:      ds,
		clock:   clk,
		bundles: make(map[spiffeid.TrustDomain]*bundleEntry),
	}
}

type bundleEntry struct {
	mu         sync.Mutex
	ts         time.Time
	bundle     *common.Bundle
	x509Bundle *x509bundle.Bundle
}

func (c *Cache) FetchBundleX509(ctx context.Context, td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	c.bundlesMtx.Lock()
	entry, ok := c.bundles[td]
	if !ok {
		entry = &bundleEntry{}
		c.bundles[td] = entry
	}
	c.bundlesMtx.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.ts.IsZero() || c.clock.Now().Sub(entry.ts) >= cacheExpiry {
		bundle, err := c.ds.FetchBundle(ctx, td.IDString())
		if err != nil {
			return nil, err
		}
		if bundle == nil {
			c.deleteEntry(td)
			return nil, nil
		}

		entry.ts = c.clock.Now()
		if proto.Equal(entry.bundle, bundle) {
			return entry.x509Bundle, nil
		}
		x509Bundle, err := parseBundle(td, bundle)
		if err != nil {
			return nil, err
		}
		entry.x509Bundle = x509Bundle
		entry.bundle = bundle
	}
	return entry.x509Bundle, nil
}

func (c *Cache) deleteEntry(td spiffeid.TrustDomain) {
	c.bundlesMtx.Lock()
	delete(c.bundles, td)
	c.bundlesMtx.Unlock()
}

// parseBundle parses a *x509bundle.Bundle from a *common.bundle.
func parseBundle(td spiffeid.TrustDomain, commonBundle *common.Bundle) (*x509bundle.Bundle, error) {
	var caCerts []*x509.Certificate
	for _, rootCA := range commonBundle.RootCas {
		rootCACerts, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("parse bundle: %w", err)
		}
		caCerts = append(caCerts, rootCACerts...)
	}

	return x509bundle.FromX509Authorities(td, caCerts), nil
}
