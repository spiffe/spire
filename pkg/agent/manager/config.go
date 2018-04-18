package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"

	tomb "gopkg.in/tomb.v2"
)

// rotatorTag is a special string used to locate the client (on the clients' pool) used to
// rotate the agent's SVID.
const rotatorTag string = "_rotator_"

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
func New(c *Config) (Manager, error) {
	c.Log = c.Log.WithField("subsystem_name", "manager")

	spiffeID, err := getSpiffeIDFromSVID(c.SVID)
	if err != nil {
		return nil, fmt.Errorf("cannot get spiffe id from SVID: %v", err)
	}

	m := &manager{
		cache: cache.New(c.Log, c.Bundle),
		c:     c,
		t:     new(tomb.Tomb),
		mtx:   new(sync.RWMutex),

		// Copy SVID into the manager to facilitate rotation
		svid:            c.SVID,
		svidKey:         c.SVIDKey,
		bundle:          c.Bundle,
		spiffeID:        spiffeID,
		serverSPIFFEID:  "spiffe://" + c.TrustDomain.Host + "/spiffe/cp",
		serverAddr:      c.ServerAddr,
		svidCachePath:   c.SVIDCachePath,
		bundleCachePath: c.BundleCachePath,
		syncFreq:        5,
		rotationFreq:    60,
	}

	err = m.newSyncClient([]string{m.spiffeID, m.serverSPIFFEID}, m.svid, m.svidKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create sync client: %v", err)
	}

	err = m.newSyncClient([]string{rotatorTag}, m.svid, m.svidKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create rotator client: %v", err)
	}

	return m, nil
}
