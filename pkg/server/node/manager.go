package node

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/datastore"
)

type PruneArgs struct {
	ExpiredFor             time.Duration
	IncludeNonReattestable bool
}

type ManagerConfig struct {
	DataStore datastore.DataStore

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	Clock clock.Clock

	PruneArgs
}

type Manager struct {
	c       ManagerConfig
	log     logrus.FieldLogger
	metrics telemetry.Metrics

	pruneRequestedCh chan PruneArgs
}

func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		c:       c,
		log:     c.Log.WithField(telemetry.RetryInterval, c.ExpiredFor),
		metrics: c.Metrics,

		pruneRequestedCh: make(chan PruneArgs, 1),
	}
}

func (m *Manager) Run(ctx context.Context) error {
	return m.pruneEvery(ctx)
}

func (m *Manager) Prune(ctx context.Context, expiredFor time.Duration, includeNonReattestable bool) {
	m.pruneRequestedCh <- PruneArgs{ExpiredFor: expiredFor, IncludeNonReattestable: includeNonReattestable}
}

func (m *Manager) pruneEvery(ctx context.Context) error {
	ticker := m.c.Clock.Ticker(m.c.ExpiredFor)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.prune(ctx, m.c.Clock.Now().Add(-m.c.ExpiredFor), m.c.IncludeNonReattestable); err != nil && ctx.Err() == nil {
				m.log.WithError(err).Error("Failed during periodic pruning of expired nodes")
			}
		case a := <-m.pruneRequestedCh:
			if err := m.prune(ctx, m.c.Clock.Now().Add(-a.ExpiredFor), a.IncludeNonReattestable); err != nil && ctx.Err() == nil {
				m.log.WithError(err).Error("Failed during on-demand pruning of expired nodes")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) prune(ctx context.Context, expiredBefore time.Time, includeNonReattestable bool) (err error) {
	counter := telemetry_server.StartNodeManagerPruneAttestedExpiredNodesCall(m.c.Metrics)
	defer counter.Done(&err)

	err = m.c.DataStore.PruneAttestedExpiredNodes(ctx, expiredBefore, includeNonReattestable)
	return err
}
