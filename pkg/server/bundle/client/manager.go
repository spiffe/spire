package client

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/datastore"
)

const (
	// attemptsPerRefreshHint is the number of attempts within the returned
	// refresh hint period that the manager will attempt to refresh the
	// bundle. It is important to try more than once within a refresh hint
	// period so we can be resilient to temporary downtime or failures.
	attemptsPerRefreshHint = 4

	// configRefreshInterval is how often the manager reloads trust domain
	// configs from the source and reconciles it against the current bundle
	// updaters.
	configRefreshInterval = time.Second * 10

	// defaultRefreshInterval is how often the manager reloads the trust bundle
	// for a trust domain if that trust domain does not specify a refresh hint in
	// its current trust bundle.
	defaultRefreshInterval = time.Minute * 5
)

type TrustDomainConfig struct {
	// EndpointURL is the URL used to fetch the bundle of the federated
	// trust domain. Is served by a SPIFFE bundle endpoint server.
	EndpointURL string

	// EndpointProfile is the bundle endpoint profile used by the
	// SPIFFE bundle endpoint server.
	EndpointProfile EndpointProfileInfo
}

type EndpointProfileInfo interface {
	// The name of the endpoint profile (e.g. "https_spiffe").
	Name() string
}

type HTTPSWebProfile struct{}

func (p HTTPSWebProfile) Name() string {
	return "https_web"
}

type HTTPSSPIFFEProfile struct {
	// EndpointSPIFFEID is the expected SPIFFE ID of the bundle endpoint server.
	EndpointSPIFFEID spiffeid.ID
}

func (p HTTPSSPIFFEProfile) Name() string {
	return "https_spiffe"
}

type ManagerConfig struct {
	Log       logrus.FieldLogger
	Metrics   telemetry.Metrics
	DataStore datastore.DataStore
	Clock     clock.Clock
	Source    TrustDomainConfigSource

	// newBundleUpdater is a test hook to inject updater behavior
	newBundleUpdater func(BundleUpdaterConfig) BundleUpdater

	// configRefreshedCh is a test hook to learn when the trust domain config
	// has been refreshed and be apprised of the next scheduled refresh.
	configRefreshedCh chan time.Duration

	// bundleRefreshedCh is a test hook to learn when a bundle has been
	// refreshed and be apprised of the next scheduled refresh.
	bundleRefreshedCh chan time.Duration
}

type Manager struct {
	log              logrus.FieldLogger
	metrics          telemetry.Metrics
	clock            clock.Clock
	ds               datastore.DataStore
	source           TrustDomainConfigSource
	configRefreshCh  chan struct{}
	configRefreshMtx sync.Mutex
	updatersMtx      sync.RWMutex
	updaters         map[spiffeid.TrustDomain]*managedBundleUpdater

	// test hooks
	newBundleUpdater  func(BundleUpdaterConfig) BundleUpdater
	configRefreshedCh chan time.Duration
	bundleRefreshedCh chan time.Duration
}

type managedBundleUpdater struct {
	BundleUpdater

	wg     sync.WaitGroup
	cancel context.CancelFunc
	runCh  chan chan error
}

func (m *managedBundleUpdater) Stop() {
	m.cancel()
	m.wg.Wait()
}

func NewManager(config ManagerConfig) *Manager {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	if config.newBundleUpdater == nil {
		config.newBundleUpdater = NewBundleUpdater
	}

	return &Manager{
		log:               config.Log,
		metrics:           config.Metrics,
		clock:             config.Clock,
		ds:                config.DataStore,
		source:            config.Source,
		newBundleUpdater:  config.newBundleUpdater,
		configRefreshCh:   make(chan struct{}, 1),
		configRefreshedCh: config.configRefreshedCh,
		bundleRefreshedCh: config.bundleRefreshedCh,
		updaters:          make(map[spiffeid.TrustDomain]*managedBundleUpdater),
	}
}

func (m *Manager) Run(ctx context.Context) error {
	// Initialize the timer that will reload the configs. The initial duration
	// isn't very important since we'll reset it after the reload has
	// completed.
	timer := m.clock.Timer(configRefreshInterval)
	defer timer.Stop()

	for {
		if err := m.refreshConfigs(ctx); err != nil {
			m.log.WithError(err).Error("Failed to reload configs")
		}
		timer.Reset(configRefreshInterval)
		m.notifyConfigRefreshed(ctx, configRefreshInterval)
		select {
		case <-m.configRefreshCh:
		case <-timer.C:
		case <-ctx.Done():
			m.log.Info("Shutting down")
			return ctx.Err()
		}
	}
}

// TriggerConfigReload triggers the manager to reload the configuration
func (m *Manager) TriggerConfigReload() {
	select {
	case m.configRefreshCh <- struct{}{}:
	default:
	}
}

// RefreshBundleFor refreshes the trust domain bundle for the given trust
// domain. If the trust domain is not managed by the manager, false is returned.
func (m *Manager) RefreshBundleFor(ctx context.Context, td spiffeid.TrustDomain) (bool, error) {
	if err := m.refreshConfigs(ctx); err != nil {
		m.log.WithError(err).Error("Failed to reload configs")
	}

	m.updatersMtx.RLock()
	updater, ok := m.updaters[td]
	m.updatersMtx.RUnlock()

	if !ok {
		return false, nil
	}

	_, _, err := updater.UpdateBundle(ctx)
	return true, err
}

func (m *Manager) refreshConfigs(ctx context.Context) error {
	m.configRefreshMtx.Lock()
	defer m.configRefreshMtx.Unlock()

	configs, err := m.source.GetTrustDomainConfigs(ctx)
	if err != nil {
		return err
	}

	// Duplicate the configs map since we're going to mutate it while figuring
	// out what needs to be started/updated/stopped.
	configs = cloneTrustDomainConfigs(configs)

	var toStop []func()
	defer func() {
		if len(toStop) > 0 {
			m.log.Debug("Stopping stale updaters")
			for _, stop := range toStop {
				stop()
			}
			m.log.Debug("Done stopping stale updaters")
		}
	}()

	m.updatersMtx.Lock()
	defer m.updatersMtx.Unlock()

	for td, updater := range m.updaters {
		tdLog := m.log.WithField(telemetry.Entry, td)
		if config, ok := configs[td]; ok {
			// Updater still needed. Update the configuration and remove it
			// from the configs list since so a new updater isn't started for
			// this trust domain.
			if updater.SetTrustDomainConfig(config) {
				tdLog.WithFields(logrus.Fields{
					telemetry.BundleEndpointURL:     config.EndpointURL,
					telemetry.BundleEndpointProfile: config.EndpointProfile.Name(),
				}).Info("Updated configuration for managed trust domain")
			}
			delete(configs, td)
		} else {
			// Updater no longer needed. Stage it to be stopped and remove it
			// from the updaters list.
			tdLog.Info("Trust domain no longer managed")
			toStop = append(toStop, updater.Stop)
			delete(m.updaters, td)
		}
	}

	// The remaining configs are for newly managed trust domains. Create and
	// start up an updater for it.
	for td, config := range configs {
		m.log.WithFields(logrus.Fields{
			telemetry.BundleEndpointURL:     config.EndpointURL,
			telemetry.BundleEndpointProfile: config.EndpointProfile.Name(),
			telemetry.TrustDomain:           td,
		}).Info("Trust domain is now managed")
		ctx, cancel := context.WithCancel(ctx)
		updater := &managedBundleUpdater{
			BundleUpdater: m.newBundleUpdater(BundleUpdaterConfig{
				TrustDomainConfig: config,
				TrustDomain:       td,
				DataStore:         m.ds,
			}),
			cancel: cancel,
			runCh:  make(chan chan error),
		}
		m.updaters[td] = updater
		updater.wg.Add(1)
		go func(td spiffeid.TrustDomain) {
			defer updater.wg.Done()
			m.runUpdater(ctx, td, updater)
		}(td)
	}
	return nil
}

func (m *Manager) runUpdater(ctx context.Context, trustDomain spiffeid.TrustDomain, updater BundleUpdater) {
	// Initialize the timer. The initial duration does not matter since it will
	// be reset with the actual refresh interval before first use.
	timer := m.clock.Timer(time.Hour)
	defer timer.Stop()

	log := m.log.WithField("trust_domain", trustDomain.Name())
	for {
		nextRefresh := m.runUpdateOnce(ctx, log, trustDomain, updater)

		log.WithFields(logrus.Fields{
			"at": m.clock.Now().Add(nextRefresh).UTC().Format(time.RFC3339),
		}).Debug("Scheduling next bundle refresh")

		// Notify the test hook
		timer.Reset(nextRefresh)

		m.notifyBundleRefreshed(ctx, nextRefresh)

		select {
		case <-timer.C:
		case <-ctx.Done():
			log.Info("No longer polling for updates")
			return
		}
	}
}

func (m *Manager) runUpdateOnce(ctx context.Context, log *logrus.Entry, trustDomain spiffeid.TrustDomain, updater BundleUpdater) time.Duration {
	log.Debug("Polling for bundle update")

	counter := telemetry_server.StartBundleManagerFetchFederatedBundleCall(m.metrics)
	counter.AddLabel(telemetry.TrustDomainID, trustDomain.Name())
	var err error
	defer counter.Done(&err)

	var localBundle, endpointBundle *spiffebundle.Bundle
	localBundle, endpointBundle, err = updater.UpdateBundle(ctx)
	if err != nil {
		log.WithError(err).Error("Error updating bundle")
	}

	if endpointBundle != nil {
		telemetry_server.IncrBundleManagerUpdateFederatedBundleCounter(m.metrics, trustDomain.Name())
		log.Info("Bundle refreshed")

		return calculateNextUpdate(endpointBundle)
	}

	if localBundle != nil {
		return calculateNextUpdate(localBundle)
	}

	// We have no bundle to use to calculate the refresh hint. Since
	// the endpoint cannot be reached without the local bundle (until
	// we implement web auth), we can retry more aggressively. This
	// refresh period determines how fast we'll respond to the local
	// bundle being bootstrapped.
	// TODO: reevaluate once we support web auth
	return bundleutil.MinimumRefreshHint
}

func (m *Manager) notifyConfigRefreshed(ctx context.Context, nextRefresh time.Duration) {
	if m.configRefreshedCh != nil {
		select {
		case m.configRefreshedCh <- nextRefresh:
		case <-ctx.Done():
		}
	}
}

func (m *Manager) notifyBundleRefreshed(ctx context.Context, nextRefresh time.Duration) {
	if m.bundleRefreshedCh != nil {
		select {
		case m.bundleRefreshedCh <- nextRefresh:
		case <-ctx.Done():
		}
	}
}

func calculateNextUpdate(b *spiffebundle.Bundle) time.Duration {
	if _, ok := b.RefreshHint(); !ok {
		return defaultRefreshInterval
	}
	return bundleutil.CalculateRefreshHint(b) / attemptsPerRefreshHint
}

func cloneTrustDomainConfigs(configs map[spiffeid.TrustDomain]TrustDomainConfig) map[spiffeid.TrustDomain]TrustDomainConfig {
	clone := make(map[spiffeid.TrustDomain]TrustDomainConfig, len(configs))
	maps.Copy(clone, configs)
	return clone
}
