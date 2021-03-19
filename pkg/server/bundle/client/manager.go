package client

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
)

const (
	// attemptsPerRefreshHint is the number of attempts within the returned
	// refresh hint period that the manager will attempt to refresh the
	// bundle. It is important to try more than once within a refresh hint
	// period so we can be resilient to temporary downtime or failures.
	attemptsPerRefreshHint = 4
)

type TrustDomainConfig struct {
	// EndpointAddress is the bundle endpoint for the trust domain.
	EndpointAddress string

	// EndpointSpiffeID is the expected SPIFFE ID of the endpoint server. If
	// unset, it defaults to the SPIRE server ID within the trust domain.
	EndpointSpiffeID spiffeid.ID

	// UseWebPKI is true if the endpoint should be authenticated with Web PKI.
	// Otherwise, SPIFFE authentication is assumed.
	UseWebPKI bool
}

type ManagerConfig struct {
	Log          logrus.FieldLogger
	Metrics      telemetry.Metrics
	DataStore    datastore.DataStore
	Clock        clock.Clock
	TrustDomains map[spiffeid.TrustDomain]TrustDomainConfig

	// newBundleUpdater is a test hook to inject updater behavior
	newBundleUpdater func(BundleUpdaterConfig) BundleUpdater
}

type Manager struct {
	log      logrus.FieldLogger
	metrics  telemetry.Metrics
	clock    clock.Clock
	updaters map[spiffeid.TrustDomain]BundleUpdater
}

func NewManager(config ManagerConfig) *Manager {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	if config.newBundleUpdater == nil {
		config.newBundleUpdater = NewBundleUpdater
	}

	updaters := make(map[spiffeid.TrustDomain]BundleUpdater)
	for trustDomain, trustDomainConfig := range config.TrustDomains {
		updaters[trustDomain] = config.newBundleUpdater(BundleUpdaterConfig{
			TrustDomainConfig: trustDomainConfig,
			TrustDomain:       trustDomain,
			DataStore:         config.DataStore,
		})
	}

	return &Manager{
		log:      config.Log,
		metrics:  config.Metrics,
		clock:    config.Clock,
		updaters: updaters,
	}
}

func (m *Manager) Run(ctx context.Context) error {
	var tasks []func(context.Context) error
	for trustDomain, updater := range m.updaters {
		// alias the loop variables that are used by the closure
		trustDomain := trustDomain
		updater := updater
		tasks = append(tasks, func(ctx context.Context) error {
			return m.runUpdater(ctx, trustDomain, updater)
		})
	}

	return util.RunTasks(ctx, tasks...)
}

func (m *Manager) runUpdater(ctx context.Context, trustDomain spiffeid.TrustDomain, updater BundleUpdater) error {
	log := m.log.WithField("trust_domain", trustDomain)
	for {
		var nextRefresh time.Duration
		log.Debug("Polling for bundle update")
		localBundle, endpointBundle, err := updater.UpdateBundle(ctx)
		if err != nil {
			log.WithError(err).Error("Error updating bundle")
		}

		switch {
		case endpointBundle != nil:
			telemetry_server.IncrBundleManagerUpdateFederatedBundleCounter(m.metrics, trustDomain.String())
			log.Info("Bundle refreshed")
			nextRefresh = calculateNextUpdate(endpointBundle)
		case localBundle != nil:
			nextRefresh = calculateNextUpdate(localBundle)
		default:
			// We have no bundle to use to calculate the refresh hint. Since
			// the endpoint cannot be reached without the local bundle (until
			// we implement web auth), we can retry more aggressively. This
			// refresh period determines how fast we'll respond to the local
			// bundle being bootstrapped.
			// TODO: reevaluate once we support web auth
			nextRefresh = bundleutil.MinimumRefreshHint
		}

		log.WithFields(logrus.Fields{
			"at": m.clock.Now().Add(nextRefresh).UTC().Format(time.RFC3339),
		}).Debug("Scheduling next bundle refresh")

		timer := m.clock.Timer(nextRefresh)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func calculateNextUpdate(b *bundleutil.Bundle) time.Duration {
	return bundleutil.CalculateRefreshHint(b) / attemptsPerRefreshHint
}
