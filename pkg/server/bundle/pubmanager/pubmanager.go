// Package pubmanager manages the publishing of the trust bundle to external
// stores through the configured BundlePublisher plugins.
package pubmanager

import (
	"context"
	"fmt"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

// NewManager creates a new bundle publishing manager.
func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		bundleUpdatedCh:  make(chan struct{}, 1),
		bundlePublishers: c.BundlePublishers,
		clock:            c.Clock,
		dataStore:        c.DataStore,
		log:              c.Log,
		trustDomain:      c.TrustDomain,
	}
}

// ManagerConfig is the config for the bundle publishing manager.
type ManagerConfig struct {
	BundlePublishers []bundlepublisher.BundlePublisher
	Clock            clock.Clock
	DataStore        datastore.DataStore
	Log              logrus.FieldLogger
	TrustDomain      spiffeid.TrustDomain
}

// Manager is the manager for bundle publishing.
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
	for {
		select {
		case <-m.bundleUpdatedCh:
			if err := m.publishBundle(ctx); err != nil && ctx.Err() == nil {
				m.log.WithError(err).Error("Failed to publish bundle")
			}
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

func (m *Manager) BundleUpdated() {
	m.drainBundleUpdated()

	if m.bundleUpdatedCh != nil {
		m.bundleUpdatedCh <- struct{}{}
	}
}

// publishBundle iterates through the configured bundle publishers and calls
// PublishBundle with the fetched bundle.
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

	errsCh := make(chan error, len(m.bundlePublishers))
	for _, bp := range m.bundlePublishers {
		bp := bp
		go func() {
			log := m.log.WithField(bp.Type(), bp.Name())
			err := bp.PublishBundle(ctx, bundle)
			if err == nil {
				log.Debug("Bundle published")
			} else {
				log.WithError(err).Error("Failed to publish bundle")
			}

			m.triggerPublishResultHook(&publishResult{
				pluginName: bp.Name(),
				bundle:     bundle,
				err:        err,
			})

			errsCh <- err
		}()
	}

	var allErrs errs.Group
	for i := 0; i < len(m.bundlePublishers); i++ {
		// Don't select on the ctx here as we can rely on the plugins to
		// respond to context cancelation and return an error.
		if err := <-errsCh; err != nil {
			allErrs.Add(err)
		}
	}
	if err := allErrs.Err(); err != nil {
		return fmt.Errorf("one or more bundle publishers returned an error: %w", err)
	}
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
// publisher). A publish action happens when there is an updated bundle in the
// datastore.
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
