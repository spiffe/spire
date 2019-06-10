package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/bundle"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"gotest.tools/assert"
)

func TestManager(t *testing.T) {
	testCases := []struct {
		name         string
		refreshHint  time.Duration
		refreshErr   error
		refreshAfter time.Duration
	}{
		{
			name:         "update refresh hint used",
			refreshHint:  time.Minute,
			refreshAfter: time.Minute,
		},
		{
			name:         "default refresh hint used ",
			refreshHint:  0,
			refreshAfter: bundle.DefaultRefreshHint,
		},
		{
			name:         "refresh hint unchanged on error ",
			refreshHint:  time.Minute,
			refreshErr:   errors.New("OHNO!"),
			refreshAfter: bundle.DefaultRefreshHint,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := clock.NewMock(t)

			updater := newFakeBundleUpdater(testCase.refreshHint, testCase.refreshErr)

			done := startManager(t, clock, updater)
			defer done()

			// wait for the initial refresh
			waitForRefresh(t, clock, testCase.refreshAfter)
			require.Equal(t, 1, updater.UpdateCount())

			// advance time and make sure another refresh happens
			clock.Add(testCase.refreshAfter + time.Millisecond)
			waitForRefresh(t, clock, testCase.refreshAfter)
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
		BootstrapBundle:  "BOOTSTRAP_BUNDLE",
	}

	manager, err := NewManager(context.Background(), ManagerConfig{
		Log:       log,
		DataStore: ds,
		Clock:     clock,
		TrustDomains: map[string]TrustDomainConfig{
			"domain.test": trustDomainConfig,
		},
		newBundleUpdater: func(ctx context.Context, config BundleUpdaterConfig) (BundleUpdater, error) {
			assert.Equal(t, trustDomainConfig, config.TrustDomainConfig)
			assert.Equal(t, "domain.test", config.TrustDomain)
			return updater, nil
		},
	})
	require.NoError(t, err)

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
	refreshHint time.Duration
	err         error

	mu          sync.Mutex
	updateCount int
}

func newFakeBundleUpdater(refreshHint time.Duration, err error) *fakeBundleUpdater {
	return &fakeBundleUpdater{
		refreshHint: refreshHint,
		err:         err,
	}
}

func (u *fakeBundleUpdater) UpdateCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.updateCount
}

func (u *fakeBundleUpdater) UpdateBundle(context.Context) (time.Duration, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.updateCount++
	return u.refreshHint, u.err
}
