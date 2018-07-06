package svid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
)

type RotatorConfig struct {
	Log            logrus.FieldLogger
	TrustDomain    url.URL
	ServerAddr     net.Addr
	ServerHostname string
	// Initial SVID and key
	SVID    *x509.Certificate
	SVIDKey *ecdsa.PrivateKey

	BundleStream observer.Stream

	SpiffeID string

	// How long to wait between expiry checks
	Interval time.Duration
}

func NewRotator(c *RotatorConfig) (*rotator, client.Client) {
	if c.Interval == 0 {
		c.Interval = 60 * time.Second
	}

	state := observer.NewProperty(State{
		SVID: c.SVID,
		Key:  c.SVIDKey,
	})

	bsm := &sync.RWMutex{}
	cfg := &client.Config{
		TrustDomain: c.TrustDomain,
		Log:         c.Log,
		Addr:        c.ServerAddr,
		Hostname:    c.ServerHostname,
		KeysAndBundle: func() (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
			s := state.Value().(State)
			bsm.RLock()
			defer bsm.RUnlock()
			bundle := c.BundleStream.Value().([]*x509.Certificate)
			return s.SVID, s.Key, bundle
		},
	}
	client := client.New(cfg)

	return &rotator{
		c:      c,
		client: client,
		state:  state,
		bsm:    bsm,
	}, client
}
