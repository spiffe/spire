package svid

import (
	"crypto"
	"crypto/x509"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
)

const DefaultRotatorInterval = 5 * time.Second

type RotatorConfig struct {
	SVIDKeyManager keymanager.SVIDKeyManager
	Log            logrus.FieldLogger
	Metrics        telemetry.Metrics
	TrustDomain    spiffeid.TrustDomain
	ServerAddr     string
	NodeAttestor   nodeattestor.NodeAttestor
	Reattestable   bool

	// Initial SVID and key
	SVID    []*x509.Certificate
	SVIDKey keymanager.Key

	BundleStream *cache.BundleStream

	// How long to wait between expiry checks
	Interval time.Duration

	// Clk is the clock that the rotator will use to create a ticker
	Clk clock.Clock

	RotationStrategy *rotationutil.RotationStrategy

	// TLSPolicy determines the post-quantum-safe policy for TLS connections.
	TLSPolicy tlspolicy.Policy
}

func NewRotator(c *RotatorConfig) (Rotator, client.Client) {
	return newRotator(c)
}

func newRotator(c *RotatorConfig) (*rotator, client.Client) {
	if c.Interval == 0 {
		c.Interval = DefaultRotatorInterval
	}

	if c.Clk == nil {
		c.Clk = clock.New()
	}

	state := observer.NewProperty(State{
		SVID:         c.SVID,
		Key:          c.SVIDKey,
		Reattestable: c.Reattestable,
	})

	rotMtx := new(sync.RWMutex)
	bsm := new(sync.RWMutex)

	cfg := &client.Config{
		TrustDomain: c.TrustDomain,
		Log:         c.Log,
		Addr:        c.ServerAddr,
		RotMtx:      rotMtx,
		KeysAndBundle: func() ([]*x509.Certificate, crypto.Signer, []*x509.Certificate) {
			s := state.Value().(State)

			bsm.RLock()
			bundles := c.BundleStream.Value()
			bsm.RUnlock()

			var rootCAs []*x509.Certificate
			if bundle := bundles[c.TrustDomain]; bundle != nil {
				rootCAs = bundle.X509Authorities()
			}
			return s.SVID, s.Key, rootCAs
		},
		TLSPolicy: c.TLSPolicy,
	}
	client := client.New(cfg)

	return &rotator{
		c:       c,
		client:  client,
		state:   state,
		clk:     c.Clk,
		backoff: backoff.NewBackoff(c.Clk, c.Interval),
		bsm:     bsm,
		rotMtx:  rotMtx,
	}, client
}
