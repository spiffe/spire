package svid

import (
	"net/url"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
)

type RotatorConfig struct {
	Catalog     catalog.Catalog
	Log         logrus.FieldLogger
	TrustDomain url.URL

	// How long to wait between expiry checks
	Interval time.Duration
}

func NewRotator(c *RotatorConfig) *rotator {
	if c.Interval == 0 {
		c.Interval = 30 * time.Second
	}

	return &rotator{
		c:     c,
		state: observer.NewProperty(State{}),
	}
}
