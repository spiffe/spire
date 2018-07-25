package svid

import (
	"net/url"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/ca"
)

type RotatorConfig struct {
	Log         logrus.FieldLogger
	TrustDomain url.URL
	ServerCA    ca.ServerCA

	// How long to wait between expiry checks
	Interval time.Duration
}

func NewRotator(c *RotatorConfig) *rotator {
	if c.Interval == 0 {
		c.Interval = 30 * time.Second
	}

	r := &rotator{
		c:     c,
		state: observer.NewProperty(State{}),
	}
	r.hooks.now = time.Now
	return r
}
