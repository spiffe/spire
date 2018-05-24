package svid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/spiffe/spire/pkg/agent/client"
	"net"
	"net/url"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
)

type RotatorConfig struct {
	Log         logrus.FieldLogger
	TrustDomain url.URL
	ServerAddr  net.Addr
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

	cfg := &client.Config{
		TrustDomain: c.TrustDomain,
		Log:         c.Log,
		Addr:        c.ServerAddr,
		KeysAndBundle: func() (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
			s := state.Value().(State)
			bundle := c.BundleStream.Value().([]*x509.Certificate)
			return s.SVID, s.Key, bundle
		},
	}
	client := client.New(cfg)

	return &rotator{
		c:      c,
		client: client,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		state:  state,
	}, client
}
