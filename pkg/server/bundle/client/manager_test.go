package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"gotest.tools/assert"
)

func TestManager(t *testing.T) {
	// create a pair of bundles with distinct refresh hints so we can assert
	// that the manager selected the correct refresh hint.
	localBundle := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "local"))
	localBundle.SetRefreshHint(time.Hour)
	endpointBundle := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "endpoint"))
	endpointBundle.SetRefreshHint(time.Hour * 2)

	testCases := []struct {
		name           string
		localBundle    *bundleutil.Bundle
		endpointBundle *bundleutil.Bundle
		nextRefresh    time.Duration
	}{
		{
			name:        "update failed to obtain local bundle",
			nextRefresh: bundleutil.MinimumRefreshHint,
		},
		{
			name:        "update failed to obtain endpoint bundle",
			localBundle: localBundle,
			nextRefresh: calculateNextUpdate(localBundle),
		},
		{
			name:           "update obtained endpoint bundle",
			localBundle:    localBundle,
			endpointBundle: endpointBundle,
			nextRefresh:    calculateNextUpdate(endpointBundle),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			clock := clock.NewMock(t)

			updater := newFakeBundleUpdater(testCase.localBundle, testCase.endpointBundle)

			done := startManager(t, clock, updater)
			defer done()

			// wait for the initial refresh
			waitForRefresh(t, clock, testCase.nextRefresh)
			require.Equal(t, 1, updater.UpdateCount())

			// advance time and make sure another refresh happens
			clock.Add(testCase.nextRefresh + time.Millisecond)
			waitForRefresh(t, clock, testCase.nextRefresh)
			require.Equal(t, 2, updater.UpdateCount())
		})
	}
}

func startManager(t *testing.T, clock clock.Clock, updater BundleUpdater) func() {
	log, _ := test.NewNullLogger()
	ds := fakedatastore.New()

	trustDomainConfig := TrustDomainConfig{
		EndpointAddress:  "ENDPOINT_ADDRESS",
		EndpointSpiffeID: "ENDPOINT_SPIFFEID",
	}

	manager := NewManager(ManagerConfig{
		Log:       log,
		DataStore: ds,
		Clock:     clock,
		TrustDomains: map[string]TrustDomainConfig{
			"domain.test": trustDomainConfig,
		},
		newBundleUpdater: func(config BundleUpdaterConfig) BundleUpdater {
			assert.Equal(t, trustDomainConfig, config.TrustDomainConfig)
			assert.Equal(t, "domain.test", config.TrustDomain)
			return updater
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- errs.New("%+v", r)
			}
		}()
		errCh <- manager.Run(ctx)
	}()

	return func() {
		cancel()
		select {
		case err := <-errCh:
			require.EqualError(t, err, "context canceled")
		case <-time.After(time.Minute):
			require.Fail(t, "timed out waiting for run to complete")
		}
	}
}

func waitForRefresh(t *testing.T, clock *clock.Mock, expectedDuration time.Duration) {
	select {
	case d := <-clock.TimerCh():
		require.Equal(t, expectedDuration, d)
	case <-time.After(time.Second * 10):
		require.Fail(t, "timed out waiting for timer creation")
	}
}

type fakeBundleUpdater struct {
	localBundle    *bundleutil.Bundle
	endpointBundle *bundleutil.Bundle

	mu          sync.Mutex
	updateCount int
}

func newFakeBundleUpdater(localBundle, endpointBundle *bundleutil.Bundle) *fakeBundleUpdater {
	return &fakeBundleUpdater{
		localBundle:    localBundle,
		endpointBundle: endpointBundle,
	}
}

func (u *fakeBundleUpdater) UpdateCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.updateCount
}

func (u *fakeBundleUpdater) UpdateBundle(context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.updateCount++
	return u.localBundle, u.endpointBundle, errors.New("UNUSED")
}
