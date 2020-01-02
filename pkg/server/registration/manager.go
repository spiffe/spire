package registration

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
)

const (
	_pruningCandence = 5 * time.Minute
)

// ManagerConfig is the config for the registration manager
type ManagerConfig struct {
	DataStore datastore.DataStore

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	Clock clock.Clock
}

// Manager is the manager of registrations
type Manager struct {
	c       ManagerConfig
	log     logrus.FieldLogger
	metrics telemetry.Metrics
}

// NewManager creates a new registration manager
func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		c:       c,
		log:     c.Log.WithField(telemetry.RetryInterval, _pruningCandence),
		metrics: c.Metrics,
	}
}

// Run runs the registration manager
func (m *Manager) Run(ctx context.Context) error {
	return m.pruneEvery(ctx)
}

func (m *Manager) pruneEvery(ctx context.Context) error {
	ticker := m.c.Clock.Ticker(_pruningCandence)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Log an error on failure unless we're shutting down
			if err := m.prune(ctx); err != nil && ctx.Err() == nil {
				m.log.WithError(err).Error("Failed pruning registration entries")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) prune(ctx context.Context) (err error) {
	counter := telemetry_server.StartRegistrationManagerPruneEntryCall(m.c.Metrics)
	defer counter.Done(&err)

	_, err = m.c.DataStore.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: m.c.Clock.Now().Unix(),
	})
	return err
}
