// Package pubmanager manages the publishing of the trust bundle to external
// stores through the configured BundlePublisher plugins.
package pubmanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"
)

const (
	// refreshInterval is the interval to check for an updated trust bundle.
	refreshInterval = 30 * time.Second
)

// ManagerConfig is the config for the bundle publishing manager.
type ManagerConfig struct {
	BundleLoadedCh chan struct{}
	Catalog        catalog.Catalog
	Clock          clock.Clock
	DataStore      datastore.DataStore
	Log            logrus.FieldLogger
	TrustDomain    spiffeid.TrustDomain
}

// Manager is the manager for bundle publishing.
type Manager struct {
	bundleLoadedCh chan struct{}
	catalog        catalog.Catalog
	clock          clock.Clock
	dataStore      datastore.DataStore
	log            logrus.FieldLogger
	trustDomain    spiffeid.TrustDomain

	hooks struct {
		// Test hook used to indicate an attempt to publish a bundle using a
		// specific bundle publisher.
		publishResultCh chan *publishResult

		// Test hook used to indicate when the action of publishing a bundle
		// has finished.
		publishmentFinishedCh chan error
	}

	bundle    *common.Bundle
	bundleMtx sync.RWMutex
}

// Run runs the bundle publishing manager.
func (m *Manager) Run(ctx context.Context) error {
	ticker := m.clock.Ticker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.bundleLoadedCh:
			m.bundleLoadedOrClockTicked(ctx)
		case <-ticker.C:
			m.bundleLoadedOrClockTicked(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) bundleLoadedOrClockTicked(ctx context.Context) {
	// Log an error on failure unless we're shutting down.
	if err := m.publishIfChanged(ctx); err != nil && ctx.Err() == nil {
		m.log.WithError(err).Error("Failed to publish bundle")
	}
}

// publishIfChanged checks if the trust bundle has changed in the datastore.
// If it changed, iterates through the configured bundle publishers and calls
// PublishBundle with the fetched bundle.
func (m *Manager) publishIfChanged(ctx context.Context) (err error) {
	bundlePubllishers := m.catalog.GetBundlePublishers()
	if len(bundlePubllishers) == 0 {
		return m.finishPublishment(nil)
	}

	bundle, err := m.dataStore.FetchBundle(ctx, m.trustDomain.IDString())
	if err != nil {
		return m.finishPublishment(fmt.Errorf("failed to fetch bundle from datastore: %w", err))
	}

	// Check if the bundle has changed.
	if proto.Equal(bundle, m.getBundle()) {
		return m.finishPublishment(nil)
	}

	// Bundle changed, update the current bundle in the manager.
	m.setBundle(bundle)

	errsCh := make(chan error, len(bundlePubllishers))
	for _, bp := range bundlePubllishers {
		go func(bp bundlepublisher.BundlePublisher) {
			err := bp.PublishBundle(ctx, bundle)
			log := m.log.WithFields(logrus.Fields{
				bp.Type(): bp.Name(),
			})
			if err == nil {
				log.Debug("Bundle published")
			} else {
				log.WithError(err).Error("Failed to publish bundle")
			}

			m.triggerPublishResultHook(&publishResult{
				bp:     bp,
				bundle: bundle,
				err:    err,
			})

			errsCh <- err
		}(bp)
	}

	var allErrs errs.Group
	for i := 0; i < len(bundlePubllishers); i++ {
		// Don't select on the ctx here as we can rely on the plugins to
		// respond to context cancelation and return an error.
		if err := <-errsCh; err != nil {
			allErrs.Add(err)
		}
	}
	if err := allErrs.Err(); err != nil {
		return m.finishPublishment(errs.New("one or more bundle publishers returned an error: %v", err))
	}
	return m.finishPublishment(nil)
}

// getBundle gets the current bundle of the manager.
func (m *Manager) getBundle() *common.Bundle {
	m.bundleMtx.RLock()
	defer m.bundleMtx.RUnlock()

	return m.bundle
}

// setBundle updates the bundle in the manager with the bundle provided.
func (m *Manager) setBundle(bundle *common.Bundle) {
	m.bundleMtx.Lock()
	defer m.bundleMtx.Unlock()

	m.bundle = bundle
}

// triggerPublishResultHook is called to know when the publish action using a
// specific bundle publisher has happened. It informs the result of calling the
// PublishBundle method to a bundle publisher.
func (m *Manager) triggerPublishResultHook(result *publishResult) {
	if m.hooks.publishResultCh != nil {
		m.hooks.publishResultCh <- result
	}
}

// finishPublishment is called to know when a publishment action has finished
// and informs if there was an error in the overall action (not specific to a
// bundle publisher). A publishment action happens when the bundle is loaded or
// after a refresh interval.
func (m *Manager) finishPublishment(err error) error {
	if m.hooks.publishmentFinishedCh != nil {
		m.hooks.publishmentFinishedCh <- err
	}

	return err
}

// publishResult holds information about the result of trying to publish a
// bundle using a specific bundle publisher.
type publishResult struct {
	bp     bundlepublisher.BundlePublisher
	bundle *common.Bundle
	err    error
}

// NewManager creates a new bundle publishing manager.
func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		bundleLoadedCh: c.BundleLoadedCh,
		catalog:        c.Catalog,
		clock:          c.Clock,
		dataStore:      c.DataStore,
		log:            c.Log,
		trustDomain:    c.TrustDomain,
	}
}
