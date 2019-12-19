package svid

import (
	"net/url"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
)

const (
	DefaultRotatorInterval = 5 * time.Second
)

type RotatorConfig struct {
	Log         logrus.FieldLogger
	Metrics     telemetry.Metrics
	TrustDomain url.URL
	ServerCA    ca.ServerCA
	Clock       clock.Clock

	// How long to wait between expiry checks
	Interval time.Duration
}

func NewRotator(c *RotatorConfig) Rotator {
	return newRotator(c)
}

func newRotator(c *RotatorConfig) *rotator {
	if c.Interval == 0 {
		c.Interval = DefaultRotatorInterval
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &rotator{
		c:     c,
		state: observer.NewProperty(State{}),
	}
}
