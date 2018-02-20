package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/spiffe/go-spiffe/uri"

	"net"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"

	proto "github.com/spiffe/spire/proto/common"
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
func New(c *Config) (*manager, error) {
	URIs, err := uri.GetURINamesFromCertificate(c.SVID)
	if err != nil {
		return nil, err
	}

	m := &manager{
		c:   c,
		t:   new(tomb.Tomb),
		mtx: new(sync.RWMutex),

		// Copy SVID into the manager to facilitate rotation
		svid:            c.SVID,
		svidKey:         c.SVIDKey,
		bundle:          c.Bundle,
		spiffeID:        URIs[0],
		serverSPIFFEID:  "spiffe://" + c.TrustDomain.Host + "/cp",
		serverAddr:      c.ServerAddr,
		regEntriesCh:    make(chan []*proto.RegistrationEntry),
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
	}
	return m, nil
}
