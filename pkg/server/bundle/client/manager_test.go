package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerPeriodicBundleRefresh(t *testing.T) {
	// create a pair of bundles with distinct refresh hints so we can assert
	// that the manager selected the correct refresh hint.
	localBundle := spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{createCACertificate(t, "local")})
	localBundle.SetRefreshHint(time.Hour)
	endpointBundle := spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{createCACertificate(t, "endpoint")})
	endpointBundle.SetRefreshHint(time.Hour * 2)
	noRefreshBundle := spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{createCACertificate(t, "endpoint")})

	source := NewTrustDomainConfigSet(TrustDomainConfigMap{
		trustDomain: TrustDomainConfig{
			EndpointURL:     "https://example.org/bundle",
			EndpointProfile: HTTPSWebProfile{},
		},
	})

	testCases := []struct {
		name           string
		localBundle    *spiffebundle.Bundle
		endpointBundle *spiffebundle.Bundle
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
		{
			name:           "endpoint bundle does not specify refresh_hint",
			localBundle:    localBundle,
			endpointBundle: noRefreshBundle,
			nextRefresh:    time.Minute * 5,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			test := newManagerTest(t, source,
				func(spiffeid.TrustDomain) *spiffebundle.Bundle {
					return testCase.localBundle
				},
				func(spiffeid.TrustDomain) *spiffebundle.Bundle {
					return testCase.endpointBundle
				},
			)

			// Wait for the config to be refreshed
			test.WaitForConfigRefresh()

			// wait for the initial bundle refresh
			test.WaitForBundleRefresh(testCase.nextRefresh)
			require.Equal(t, 1, test.UpdateCount(trustDomain))

			// advance time and make sure another bundle refresh happens
			test.AdvanceTime(testCase.nextRefresh + time.Millisecond)
			test.WaitForBundleRefresh(testCase.nextRefresh)
			require.Equal(t, 2, test.UpdateCount(trustDomain))
		})
	}
}

func TestManagerOnDemandBundleRefresh(t *testing.T) {
	configSet := NewTrustDomainConfigSet(nil)

	test := newManagerTest(t, configSet, nil, nil)

	// Wait for the config to be refreshed
	test.WaitForConfigRefresh()

	// Assert the trust domain is not known to the manager
	has, err := test.RefreshBundleFor(trustDomain)
	assert.False(t, has, "manager should not know about the trust domain")
	assert.NoError(t, err)
	assert.Equal(t, -1, test.UpdateCount(trustDomain))

	// Now, add the trust domain configuration to the source and assert
	// that refreshing the bundle reloads configs from the source.
	configSet.Set(trustDomain, TrustDomainConfig{
		EndpointURL:     "https://some-domain.test/bundle",
		EndpointProfile: HTTPSWebProfile{},
	})

	has, err = test.RefreshBundleFor(trustDomain)
	assert.True(t, has, "manager should know about the trust domain")
	assert.EqualError(t, err, "OHNO")

	// The update count may be more than 1, since RefreshBundle will update the
	// bundle, but also, since the trust domain is newly managed, kick off a
	// goroutine that will refresh it as well.
	assert.Greater(t, test.UpdateCount(trustDomain), 0)
}

func TestManagerConfigPeriodicRefresh(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("domain1.test")
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	td3 := spiffeid.RequireTrustDomainFromString("domain3.test")

	configWebA := TrustDomainConfig{
		EndpointURL:     "https://some-domain.test/webA",
		EndpointProfile: HTTPSWebProfile{},
	}
	configWebB := TrustDomainConfig{
		EndpointURL:     "https://some-domain.test/webB",
		EndpointProfile: HTTPSWebProfile{},
	}
	configSPIFFEA := TrustDomainConfig{
		EndpointURL: "https://some-domain.test/spiffeA",
		EndpointProfile: HTTPSSPIFFEProfile{
			EndpointSPIFFEID: spiffeid.RequireFromString("spiffe://some-domain.test/spiffeA"),
		},
	}
	configSPIFFEB := TrustDomainConfig{
		EndpointURL: "https://some-domain.test/spiffeB",
		EndpointProfile: HTTPSSPIFFEProfile{
			EndpointSPIFFEID: spiffeid.RequireFromString("spiffe://some-domain.test/spiffeB"),
		},
	}

	configSet := NewTrustDomainConfigSet(TrustDomainConfigMap{
		td1: configSPIFFEA,
		td2: configWebA,
	})

	test := newManagerTest(t, configSet, nil, nil)

	// Wait until the config is refreshed and a bundle refresh happens
	test.WaitForConfigRefresh()
	test.WaitForBundleRefresh(bundleutil.MinimumRefreshHint) // td1
	test.WaitForBundleRefresh(bundleutil.MinimumRefreshHint) // td2

	// Assert that we have configuration for td1 and td2, but not td3 and that
	// update attempts were made on td1 and td2, but that td3 is unknown to
	// the manager.
	require.Equal(t, map[spiffeid.TrustDomain]TrustDomainConfig{
		td1: configSPIFFEA,
		td2: configWebA,
	}, test.GetTrustDomainConfigs())
	assert.Equal(t, 1, test.UpdateCount(td1))
	assert.Equal(t, 1, test.UpdateCount(td2))
	assert.Equal(t, -1, test.UpdateCount(td3))

	// Now adjust the configuration to drop td1, change td2, and introduce td3.
	// Both td2 and td3 should have an extra update count. td1 update count will
	// remain the same.
	configSet.SetAll(TrustDomainConfigMap{
		td2: configSPIFFEB,
		td3: configWebB,
	})

	// Wait until the config is refreshed and a bundle refresh happens
	test.AdvanceTime(bundleutil.MinimumRefreshHint + time.Millisecond)
	test.WaitForConfigRefresh()
	test.WaitForBundleRefresh(bundleutil.MinimumRefreshHint) // td2
	test.WaitForBundleRefresh(bundleutil.MinimumRefreshHint) // td3

	require.Equal(t, map[spiffeid.TrustDomain]TrustDomainConfig{
		td1: configSPIFFEA,
		td2: configSPIFFEB,
		td3: configWebB,
	}, test.GetTrustDomainConfigs())
	assert.Equal(t, 1, test.UpdateCount(td1))
	assert.Equal(t, 2, test.UpdateCount(td2))
	assert.Equal(t, 1, test.UpdateCount(td3))
}

func TestManagerConfigManualRefresh(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("domain1.test")
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	config1 := TrustDomainConfig{
		EndpointURL:     "https://domain1.test/bundle",
		EndpointProfile: HTTPSWebProfile{},
	}
	config2 := TrustDomainConfig{
		EndpointURL:     "https://domain2.test/bundle",
		EndpointProfile: HTTPSWebProfile{},
	}

	configSet := NewTrustDomainConfigSet(TrustDomainConfigMap{
		td1: config1,
	})

	test := newManagerTest(t, configSet, nil, nil)

	// Wait for the original config to be loaded
	test.WaitForConfigRefresh()
	require.Equal(t, map[spiffeid.TrustDomain]TrustDomainConfig{
		td1: config1,
	}, test.GetTrustDomainConfigs())

	// Update config and trigger the reload
	configSet.Set(td2, config2)
	test.manager.TriggerConfigReload()
	test.WaitForConfigRefresh()
	require.Equal(t, map[spiffeid.TrustDomain]TrustDomainConfig{
		td1: config1,
		td2: config2,
	}, test.GetTrustDomainConfigs())
}

type managerTest struct {
	t                 *testing.T
	clock             *clock.Mock
	localBundles      func(spiffeid.TrustDomain) *spiffebundle.Bundle
	endpointBundles   func(spiffeid.TrustDomain) *spiffebundle.Bundle
	bundleUpdatersMtx sync.Mutex
	bundleUpdaters    map[spiffeid.TrustDomain]*fakeBundleUpdater
	configRefreshedCh chan time.Duration
	bundleRefreshedCh chan time.Duration
	manager           *Manager
}

func newManagerTest(t *testing.T, source TrustDomainConfigSource, localBundles, endpointBundles func(spiffeid.TrustDomain) *spiffebundle.Bundle) *managerTest {
	log, _ := test.NewNullLogger()

	if localBundles == nil {
		localBundles = func(spiffeid.TrustDomain) *spiffebundle.Bundle { return nil }
	}
	if endpointBundles == nil {
		endpointBundles = func(spiffeid.TrustDomain) *spiffebundle.Bundle { return nil }
	}

	test := &managerTest{
		t:                 t,
		clock:             clock.NewMock(t),
		localBundles:      localBundles,
		endpointBundles:   endpointBundles,
		bundleUpdaters:    make(map[spiffeid.TrustDomain]*fakeBundleUpdater),
		configRefreshedCh: make(chan time.Duration),
		bundleRefreshedCh: make(chan time.Duration),
	}

	test.manager = NewManager(ManagerConfig{
		Log:               log,
		Metrics:           telemetry.Blackhole{},
		DataStore:         fakedatastore.New(t),
		Clock:             test.clock,
		Source:            source,
		newBundleUpdater:  test.newBundleUpdater,
		configRefreshedCh: test.configRefreshedCh,
		bundleRefreshedCh: test.bundleRefreshedCh,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("%+v", r)
			}
		}()
		errCh <- test.manager.Run(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			require.EqualError(t, err, "context canceled")
		case <-time.After(time.Minute):
			require.Fail(t, "timed out waiting for run to complete")
		}
	})

	return test
}

func (test *managerTest) AdvanceTime(dt time.Duration) {
	test.clock.Add(dt)
}

func (test *managerTest) UpdateCount(td spiffeid.TrustDomain) int {
	bundleUpdater, ok := test.bundleUpdaterFor(td)
	if !ok {
		return -1
	}
	return bundleUpdater.UpdateCount()
}

func (test *managerTest) GetTrustDomainConfigs() map[spiffeid.TrustDomain]TrustDomainConfig {
	test.bundleUpdatersMtx.Lock()
	defer test.bundleUpdatersMtx.Unlock()

	configs := make(map[spiffeid.TrustDomain]TrustDomainConfig)
	for td, bundleUpdater := range test.bundleUpdaters {
		configs[td] = bundleUpdater.GetTrustDomainConfig()
	}
	return configs
}

func (test *managerTest) WaitForConfigRefresh() {
	select {
	case d := <-test.configRefreshedCh:
		require.Equal(test.t, configRefreshInterval, d, "next config refresh not at the expected interval")
	case <-time.After(time.Second * 10):
		require.Fail(test.t, "timed out waiting for config refresh")
	}
}

func (test *managerTest) WaitForBundleRefresh(expectNextRefresh time.Duration) {
	select {
	case d := <-test.bundleRefreshedCh:
		require.Equal(test.t, expectNextRefresh, d, "next bundle refresh not at the expected interval")
	case <-time.After(time.Second * 10):
		require.Fail(test.t, "timed out waiting for bundle refresh")
	}
}

func (test *managerTest) RefreshBundleFor(td spiffeid.TrustDomain) (bool, error) {
	return test.manager.RefreshBundleFor(context.Background(), td)
}

func (test *managerTest) newBundleUpdater(config BundleUpdaterConfig) BundleUpdater {
	bundleUpdater := newFakeBundleUpdater(config)
	bundleUpdater.SetBundles(
		test.localBundles(config.TrustDomain),
		test.endpointBundles(config.TrustDomain),
	)

	test.bundleUpdatersMtx.Lock()
	defer test.bundleUpdatersMtx.Unlock()
	test.bundleUpdaters[config.TrustDomain] = bundleUpdater
	return bundleUpdater
}

func (test *managerTest) bundleUpdaterFor(td spiffeid.TrustDomain) (*fakeBundleUpdater, bool) {
	test.bundleUpdatersMtx.Lock()
	defer test.bundleUpdatersMtx.Unlock()
	updater, ok := test.bundleUpdaters[td]
	return updater, ok
}

type fakeBundleUpdater struct {
	mtx            sync.Mutex
	localBundle    *spiffebundle.Bundle
	endpointBundle *spiffebundle.Bundle
	updateCount    int
	config         BundleUpdaterConfig
}

func newFakeBundleUpdater(config BundleUpdaterConfig) *fakeBundleUpdater {
	return &fakeBundleUpdater{
		config: config,
	}
}

func (u *fakeBundleUpdater) SetBundles(localBundle, endpointBundle *spiffebundle.Bundle) {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	u.localBundle = localBundle
	u.endpointBundle = endpointBundle
}

func (u *fakeBundleUpdater) UpdateCount() int {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	return u.updateCount
}

func (u *fakeBundleUpdater) UpdateBundle(context.Context) (*spiffebundle.Bundle, *spiffebundle.Bundle, error) {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	u.updateCount++
	return u.localBundle, u.endpointBundle, errors.New("OHNO")
}

func (u *fakeBundleUpdater) GetTrustDomainConfig() TrustDomainConfig {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	return u.config.TrustDomainConfig
}

func (u *fakeBundleUpdater) SetTrustDomainConfig(trustDomainConfig TrustDomainConfig) bool {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	if u.config.TrustDomainConfig != trustDomainConfig {
		u.config.TrustDomainConfig = trustDomainConfig
		return true
	}
	return false
}
