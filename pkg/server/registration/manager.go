package registration

import (
	"context"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/server/datastore"
)

const (
	_warningCadence = 60
)

// ManagerConfig is the config for the registration manager
type ManagerConfig struct {
	RegistrationPruning time.Duration
	DataStore           datastore.DataStore

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
		log:     c.Log.WithField(telemetry.RetryInterval, c.RegistrationPruning),
		metrics: c.Metrics,
	}
}

// Run runs the registration manager
func (m *Manager) Run(ctx context.Context) error {
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return m.pruneEvery(ctx)
		},
	)
	if err == context.Canceled {
		err = nil
	}
	return err
}

func (m *Manager) pruneEvery(ctx context.Context) error {
	if m.c.RegistrationPruning <= 0 {
		m.log.Info("automatic registration pruning not enabled")
		return nil
	}
	if m.c.RegistrationPruning.Seconds() <= _warningCadence {
		m.log.Warn("automatic registration pruning cadence may be too frequent")
	}

	ticker := m.c.Clock.Ticker(m.c.RegistrationPruning)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.prune(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) prune(ctx context.Context) (err error) {
	counter := telemetry_server.StartRegistrationManagerPruneEntryCall(m.c.Metrics)
	defer counter.Done(&err)

	// drop response output
	_, err = m.c.DataStore.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: m.c.Clock.Now().Unix(),
	})

	if err != nil {
		return fmt.Errorf("unable to prune registration entries: %v", err)
	}

	return nil
}
