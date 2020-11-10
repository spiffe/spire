package entrycache

import (
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	entryCacheReloadInterval = 5 * time.Second
)

type HydratorConfig struct {
	Clock      clock.Clock
	EntryCache Cache
	Interval   time.Duration
	Log        logrus.FieldLogger
	Metrics    telemetry.Metrics
}

func NewHydrator(config *HydratorConfig) *Hydrator {
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	if config.Interval == 0 {
		config.Interval = entryCacheReloadInterval
	}

	return &Hydrator{
		c: config,
	}
}
