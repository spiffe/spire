// Package pubmanager manages the publishing of the trust bundle to external
// stores through the configured BundlePublisher plugins.
package pubmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	// refreshInterval is the interval to check for an updated trust bundle.
	refreshInterval = 30 * time.Second
)

// PubManager provides an abstraction for a bundle publishing manager that can
// run in the background (publishing the bundle periodically) and react to
// updates in the bundle.
type PubManager interface {
	BundleUpdated()
	Init(bundlePublishers []bundlepublisher.BundlePublisher, dataStore datastore.DataStore)
	Run(ctx context.Context) error
}

// NewManager creates a new bundle publishing manager.
func NewManager(c *ManagerConfig) PubManager {
	return newManager(c)
}

// ManagerConfig is the config for the bundle publishing manager.
type ManagerConfig struct {
	BundlePublishers []bundlepublisher.BundlePublisher
	Clock            clock.Clock
	Log              logrus.FieldLogger
	TrustDomain      spiffeid.TrustDomain
}

// Manager is the manager for bundle publishing. It implements the PubManager
// interface.
type Manager struct {
	bundleUpdatedCh  chan struct{}
	bundlePublishers []bundlepublisher.BundlePublisher
	clock            clock.Clock
	dataStore        datastore.DataStore
	log              logrus.FieldLogger
	trustDomain      spiffeid.TrustDomain

	hooks struct {
		// Test hook used to indicate an attempt to publish a bundle using a
		// specific bundle publisher.
		publishResultCh chan *publishResult

		// Test hook used to indicate when the action of publishing a bundle
		// has finished.
		publishedCh chan error
	}
}

// Run runs the bundle publishing manager.
func (m *Manager) Run(ctx context.Context) error {
	if m.dataStore == nil {
		return errors.New("missing datastore")
	}

	if m.trustDomain.IsZero() {
		return errors.New("missing trust domain")
	}

	ticker := m.clock.Ticker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.callPublishBundle(ctx)
		case <-m.bundleUpdatedCh:
			m.callPublishBundle(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

// Init initializes the bundle publishing manager.
func (m *Manager) Init(bundlePublishers []bundlepublisher.BundlePublisher, dataStore datastore.DataStore) {
	m.bundlePublishers = bundlePublishers
	m.dataStore = dataStore
}

// BundleUpdated tells the bundle publishing manager that the bundle has been
// updates and forces a PublishBundle operation on all the plugins.
func (m *Manager) BundleUpdated() {
	m.drainBundleUpdated()

	if m.bundleUpdatedCh != nil {
		m.bundleUpdatedCh <- struct{}{}
	}
}

// callPublishBundle calls the publishBundle function and logs if there was an
// error.
func (m *Manager) callPublishBundle(ctx context.Context) {
	if err := m.publishBundle(ctx); err != nil && ctx.Err() == nil {
		m.log.WithError(err).Error("Failed to publish bundle")
	}
}

// publishBundle iterates through the configured bundle publishers and calls
// PublishBundle with the fetched bundle. This function only returns an error
// if bundle publishers can't be called due to a failure fetching the bundle
// from the datastore.
func (m *Manager) publishBundle(ctx context.Context) (err error) {
	defer func() {
		m.publishDone(err)
	}()

	if len(m.bundlePublishers) == 0 {
		return nil
	}

	bundle, err := m.dataStore.FetchBundle(ctx, m.trustDomain.IDString())
	if err != nil {
		return fmt.Errorf("failed to fetch bundle from datastore: %w", err)
	}

	for _, bp := range m.bundlePublishers {
		bp := bp
		go func() {
			log := m.log.WithField(bp.Type(), bp.Name())
			err := bp.PublishBundle(ctx, bundle)
			if err != nil {
				log.WithError(err).Error("Failed to publish bundle")
			}

			m.triggerPublishResultHook(&publishResult{
				pluginName: bp.Name(),
				bundle:     bundle,
				err:        err,
			})
		}()
	}

	// Rather than holding waiting for a result of each PublishBundle action,
	// this function returns without error here because all bundle publishers
	// could be called. Is the responsibility of each plugin to handle failure
	// conditions when publishing a bundle and implement a retry logic if
	// needed.
	return nil
}

// triggerPublishResultHook is called to know when the publish action using a
// specific bundle publisher has happened. It informs the result of calling the
// PublishBundle method to a bundle publisher.
func (m *Manager) triggerPublishResultHook(result *publishResult) {
	if m.hooks.publishResultCh != nil {
		m.hooks.publishResultCh <- result
	}
}

// publishDone is called to know when a publish action has finished and informs
// if there was an error in the overall action (not specific to a bundle
// publisher). A publish action happens periodically (every refreshInterval) and
// also when BundleUpdated() is called.
func (m *Manager) publishDone(err error) {
	if m.hooks.publishedCh != nil {
		m.hooks.publishedCh <- err
	}
}

// publishResult holds information about the result of trying to publish a
// bundle using a specific bundle publisher.
type publishResult struct {
	pluginName string
	bundle     *common.Bundle
	err        error
}

func (m *Manager) drainBundleUpdated() {
	select {
	case <-m.bundleUpdatedCh:
	default:
	}
}

func newManager(c *ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		bundleUpdatedCh:  make(chan struct{}, 1),
		bundlePublishers: c.BundlePublishers,
		clock:            c.Clock,
		log:              c.Log,
		trustDomain:      c.TrustDomain,
	}
}
