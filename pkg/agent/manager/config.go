package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"

	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	// Agent SVID and key resulting from successful attestation.
	SVID    *x509.Certificate
	SVIDKey *ecdsa.PrivateKey

	Catalog     catalog.Catalog
	TrustDomain url.URL

	Log logrus.FieldLogger
}

func New(c *Config) *manager {
	m := &manager{
		c:   c,
		t:   new(tomb.Tomb),
		mtx: new(sync.RWMutex),

		// Copy SVID into the manager to facilitate rotation
		svid:    c.SVID,
		svidKey: c.SVIDKey,
	}

	return m
}
