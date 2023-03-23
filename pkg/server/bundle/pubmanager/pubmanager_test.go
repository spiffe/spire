package pubmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

var (
	td = spiffeid.RequireTrustDomainFromString("spiffe://example.org")

	bp1Success = &fakeBundlePublisher{
		pluginName: "plugin-1",
		pluginType: "bundle-publisher-plugin-1",
	}

	bp2Success = &fakeBundlePublisher{
		pluginName: "plugin-2",
		pluginType: "bundle-publisher-plugin-2",
	}

	bp3Error = &fakeBundlePublisher{
		pluginName: "plugin-3",
		pluginType: "bundle-publisher-plugin-3",
		err:        errors.New("error publishing bundle"),
	}
)

type publishResults map[string]*publishResult

type managerTest struct {
	clockHook        *clock.Mock
	datastore        *fakedatastore.DataStore
	logHook          *test.Hook
	bundlePublishers map[string]bundlepublisher.BundlePublisher
	m                *Manager
}

func (test *managerTest) waitForPublishResult(t *testing.T, expectedResults publishResults) {
	for i := 0; i < len(expectedResults); i++ {
		select {
		case bpe := <-test.m.hooks.publishResultCh:
			expectedBPEvent, ok := expectedResults[bpe.bp.Name()]
			require.True(t, ok)
			require.Equal(t, expectedBPEvent.bp.Name(), bpe.bp.Name())
			require.Equal(t, expectedBPEvent.bp.Type(), bpe.bp.Type())
			spiretest.AssertProtoEqual(t, expectedBPEvent.bundle, bpe.bundle)
			if bpe.err == nil {
				require.NoError(t, expectedBPEvent.err)
			} else {
				require.EqualError(t, expectedBPEvent.err, bpe.err.Error())
			}

		case <-time.After(time.Second * 15):
			require.FailNow(t, "timed out waiting for bundle publishment")
		}
	}
}

func (test *managerTest) waitForPublishmentFinished(t *testing.T, expectedErr string) {
	select {
	case err := <-test.m.hooks.publishmentFinishedCh:
		if expectedErr != "" {
			require.EqualError(t, err, expectedErr)
			return
		}
		require.NoError(t, err)
	case <-time.After(time.Second * 15):
		require.FailNow(t, "timed out waiting for finishing publishment")
	}
}

func setupTest(t *testing.T, bundlePublishers []bundlepublisher.BundlePublisher) *managerTest {
	catalog := fakeservercatalog.New()
	catalog.BundlePublishers = bundlePublishers
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	ds := fakedatastore.New(t)

	clock := clock.NewMock(t)
	m := NewManager(ManagerConfig{
		BundleLoadedCh: make(chan struct{}, 1),
		Catalog:        catalog,
		Clock:          clock,
		DataStore:      ds,
		Log:            log,
		TrustDomain:    td,
	})
	m.hooks.publishResultCh = make(chan *publishResult, 10)
	m.hooks.publishmentFinishedCh = make(chan error)
	bundlePublishersMap := make(map[string]bundlepublisher.BundlePublisher)
	for _, bp := range bundlePublishers {
		bundlePublishersMap[bp.Name()] = bp
	}
	return &managerTest{
		bundlePublishers: bundlePublishersMap,
		clockHook:        clock,
		datastore:        ds,
		logHook:          logHook,
		m:                m,
	}
}

func TestRun(t *testing.T) {
	b := getNewBundle(t)

	for _, tt := range []struct {
		name             string
		expecteResults   publishResults
		expectedErr      string
		bundlePublishers []bundlepublisher.BundlePublisher
	}{
		{
			name:             "one bundle publisher - success",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success},
			expecteResults: publishResults{
				bp1Success.pluginName: {
					bp:     bp1Success,
					bundle: b,
				},
			},
		},
		{
			name:             "more than one bundle publisher - success",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success, bp2Success},
			expecteResults: publishResults{
				bp1Success.pluginName: {
					bp:     bp1Success,
					bundle: b,
				},
				bp2Success.pluginName: {
					bp:     bp2Success,
					bundle: b,
				},
			},
		},
		{
			name:             "one bundle publisher - error",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp3Error},
			expecteResults: publishResults{
				bp3Error.pluginName: {
					bp:     bp3Error,
					bundle: b,
					err:    bp3Error.err,
				},
			},
			expectedErr: "one or more bundle publishers returned an error: error publishing bundle",
		},
		{
			name:             "success and error",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success, bp2Success, bp3Error},
			expecteResults: publishResults{
				bp1Success.pluginName: {
					bp:     bp1Success,
					bundle: b,
				},
				bp2Success.pluginName: {
					bp:     bp2Success,
					bundle: b,
				},
				bp3Error.pluginName: {
					bp:     bp3Error,
					bundle: b,
					err:    bp3Error.err,
				},
			},
			expectedErr: "one or more bundle publishers returned an error: error publishing bundle",
		},
		{
			name: "no bundle publishers",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, tt.bundlePublishers)
			done := runManager(t, test)
			defer done()

			// Update the local bundle in the datastore with the initial bundle.
			_, err := test.m.dataStore.AppendBundle(context.Background(), b)
			require.NoError(t, err)

			// Trigger the bundle loaded event.
			test.m.bundleLoadedCh <- struct{}{}

			test.waitForPublishResult(t, tt.expecteResults)
			test.waitForPublishmentFinished(t, tt.expectedErr)

			// Advance time enough that a refresh should happen.
			test.clockHook.Add(refreshInterval + time.Millisecond)
			test.waitForPublishmentFinished(t, "")

			// Generate a new bundle.
			updatedBundle := getNewBundle(t)

			// Update the local bundle in the datastore.
			require.NoError(t, err)
			newBundle, err := test.m.dataStore.AppendBundle(context.Background(), updatedBundle)
			require.NoError(t, err)

			// Update the expected published bundle with the new bundle.
			for _, ebp := range tt.expecteResults {
				ebp.bundle = newBundle
			}

			// Advance time enough that a refresh should happen.
			test.clockHook.Add(refreshInterval + time.Millisecond)
			if len(tt.expecteResults) > 0 {
				test.waitForPublishResult(t, tt.expecteResults)
			}
			test.waitForPublishmentFinished(t, tt.expectedErr)

			// Cover the case where there is a failure fetching the bundle from
			// the datastore.
			test.datastore.SetNextError(errors.New("datastore error"))

			// Advance time enough that a refresh should happen.
			test.clockHook.Add(refreshInterval + time.Millisecond)

			if len(tt.bundlePublishers) == 0 {
				// There are no publishers, so there shouldn't be an attempt to
				// fetch bundles from the datastore. No error should happen.
				test.waitForPublishmentFinished(t, "")
				return
			}

			// There are bundle publishers and fetching from the datastore
			// should result in an error.
			test.waitForPublishmentFinished(t, "failed to fetch bundle from datastore: datastore error")
		})
	}
}

func runManager(t *testing.T, test *managerTest) (done func()) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- test.m.Run(ctx)
	}()
	return func() {
		cancel()
		require.NoError(t, <-errCh)
	}
}

type fakeBundlePublisher struct {
	bundlepublisher.BundlePublisher

	mu         sync.RWMutex
	pluginName string
	pluginType string
	err        error
}

// PublishBundle is a fake implementation for the PublishBundle method.
func (p *fakeBundlePublisher) PublishBundle(ctx context.Context, bundle *common.Bundle) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.err != nil {
		return p.err
	}

	return nil
}

// Name returns the plugin name of the fake bundle publisher plugin.
func (p *fakeBundlePublisher) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.pluginName
}

// Name returns the plugin type of the fake bundle publisher plugin.
func (p *fakeBundlePublisher) Type() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.pluginType
}

// getNewBundle returns a generated *common.Bundle for testing.
func getNewBundle(t *testing.T) *common.Bundle {
	return &common.Bundle{
		TrustDomainId: td.IDString(),
		RootCas:       []*common.Certificate{{DerBytes: testca.New(t, td).X509Authorities()[0].Raw}},
	}
}
