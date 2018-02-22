package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/cache"

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
	ServerAddr      *net.TCPAddr
	SVIDCachePath   string
	BundleCachePath string
}

// New creates a cache manager based on c's configuration
func New(c *Config) (Manager, error) {
	c.Log = c.Log.WithField("subsystem_name", "manager")

	URIs, err := uri.GetURINamesFromCertificate(c.SVID)
	if err != nil {
		return nil, err
	}

	m := &manager{
		cache: cache.New(c.Log),
		c:     c,
		t:     new(tomb.Tomb),
		mtx:   new(sync.RWMutex),

		// Copy SVID into the manager to facilitate rotation
		svid:            c.SVID,
		svidKey:         c.SVIDKey,
		bundle:          c.Bundle,
		spiffeID:        URIs[0],
		serverSPIFFEID:  "spiffe://" + c.TrustDomain.Host + "/cp",
		serverAddr:      c.ServerAddr,
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
	}
	return m, nil
}
