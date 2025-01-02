package pubmanager

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td = spiffeid.RequireTrustDomainFromString("spiffe://example.org")
)

func TestRun(t *testing.T) {
	var (
		bp1Success = &fakeBundlePublisher{
			pluginName: "plugin-1",
		}

		bp2Success = &fakeBundlePublisher{
			pluginName: "plugin-2",
		}

		bp3Error = &fakeBundlePublisher{
			pluginName: "plugin-3",
			err:        errors.New("error publishing bundle"),
		}

		bundle1 = &common.Bundle{
			TrustDomainId: td.IDString(),
			RootCas:       []*common.Certificate{{DerBytes: testca.New(t, td).X509Authorities()[0].Raw}},
		}

		bundle2 = &common.Bundle{
			TrustDomainId: td.IDString(),
			RootCas:       []*common.Certificate{{DerBytes: testca.New(t, td).X509Authorities()[0].Raw}},
		}
	)

	for _, tt := range []struct {
		name             string
		expectedResults  publishResults
		expectedErr      string
		datastoreError   string
		bundlePublishers []bundlepublisher.BundlePublisher
	}{
		{
			name:             "one bundle publisher - success",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success},
			expectedResults: publishResults{
				bp1Success.pluginName: {
					pluginName: bp1Success.pluginName,
					bundle:     bundle1,
				},
			},
		},
		{
			name:             "more than one bundle publisher - success",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success, bp2Success},
			expectedResults: publishResults{
				bp1Success.pluginName: {
					pluginName: bp1Success.pluginName,
					bundle:     bundle1,
				},
				bp2Success.pluginName: {
					pluginName: bp2Success.pluginName,
					bundle:     bundle1,
				},
			},
		},
		{
			name:             "one bundle publisher - error",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp3Error},
			expectedResults: publishResults{
				bp3Error.pluginName: {
					pluginName: bp3Error.pluginName,
					bundle:     bundle1,
					err:        bp3Error.err,
				},
			},
		},
		{
			name:             "success and error",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success, bp2Success, bp3Error},
			expectedResults: publishResults{
				bp1Success.pluginName: {
					pluginName: bp1Success.pluginName,
					bundle:     bundle1,
				},
				bp2Success.pluginName: {
					pluginName: bp2Success.pluginName,
					bundle:     bundle1,
				},
				bp3Error.pluginName: {
					pluginName: bp3Error.pluginName,
					bundle:     bundle1,
					err:        bp3Error.err,
				},
			},
		},
		{
			name:             "no bundle publishers",
			bundlePublishers: []bundlepublisher.BundlePublisher{},
		},
		{
			name:             "datastore error",
			bundlePublishers: []bundlepublisher.BundlePublisher{bp1Success},
			datastoreError:   "error in datastore",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, tt.bundlePublishers)
			done := runManager(t, test)
			defer done()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// Update the local bundle in the datastore with the initial bundle.
			_, err := test.m.dataStore.AppendBundle(ctx, bundle1)
			require.NoError(t, err)

			// Trigger the bundle updated event.
			test.m.BundleUpdated()
			test.waitForPublishResult(ctx, t, tt.expectedResults)
			test.waitForPublishFinished(ctx, t, tt.expectedErr)

			// Update the local bundle in the datastore.
			newBundle, err := test.m.dataStore.AppendBundle(ctx, bundle2)
			require.NoError(t, err)

			// Update the expected published bundle with the new bundle.
			for _, ebp := range tt.expectedResults {
				ebp.bundle = newBundle
			}

			// Trigger the bundle updated event.
			test.m.BundleUpdated()
			test.waitForPublishResult(ctx, t, tt.expectedResults)
			test.waitForPublishFinished(ctx, t, tt.expectedErr)

			// Advance time enough that a refresh should happen.
			test.clockHook.Add(refreshInterval + time.Millisecond)
			test.waitForPublishResult(ctx, t, tt.expectedResults)
			test.waitForPublishFinished(ctx, t, tt.expectedErr)

			if tt.datastoreError != "" {
				// Cover the case where there is a failure fetching the bundle
				// from the datastore.
				test.datastore.SetNextError(errors.New(tt.datastoreError))

				// Trigger the bundle updated event.
				test.m.BundleUpdated()
				test.waitForPublishFinished(ctx, t, fmt.Sprintf("failed to fetch bundle from datastore: %s", tt.datastoreError))
			}
		})
	}
}

type publishResults map[string]*publishResult

type managerTest struct {
	clockHook        *clock.Mock
	datastore        *fakedatastore.DataStore
	logHook          *test.Hook
	bundlePublishers map[string]bundlepublisher.BundlePublisher
	m                *Manager
}

func (test *managerTest) waitForPublishResult(ctx context.Context, t *testing.T, expectedResults publishResults) {
	for range expectedResults {
		select {
		case bpe := <-test.m.hooks.publishResultCh:
			expectedBPEvent, ok := expectedResults[bpe.pluginName]
			require.True(t, ok)
			require.Equal(t, expectedBPEvent.pluginName, bpe.pluginName)
			spiretest.AssertProtoEqual(t, expectedBPEvent.bundle, bpe.bundle)
			if expectedBPEvent.err == nil {
				require.NoError(t, bpe.err)
			} else {
				require.EqualError(t, bpe.err, expectedBPEvent.err.Error())
			}
		case <-ctx.Done():
			assert.Fail(t, "context is finished")
		}
	}
}

func (test *managerTest) waitForPublishFinished(ctx context.Context, t *testing.T, expectedErr string) {
	select {
	case err := <-test.m.hooks.publishedCh:
		if expectedErr != "" {
			require.EqualError(t, err, expectedErr)
			return
		}
		require.NoError(t, err)
	case <-ctx.Done():
		assert.Fail(t, "context is finished")
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
func (p *fakeBundlePublisher) PublishBundle(context.Context, *common.Bundle) error {
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

func setupTest(t *testing.T, bundlePublishers []bundlepublisher.BundlePublisher) *managerTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	ds := fakedatastore.New(t)

	clock := clock.NewMock(t)
	m, err := newManager(&ManagerConfig{
		BundlePublishers: bundlePublishers,
		DataStore:        ds,
		Clock:            clock,
		Log:              log,
		TrustDomain:      td,
	})

	require.NoError(t, err)

	m.hooks.publishResultCh = make(chan *publishResult, 10)
	m.hooks.publishedCh = make(chan error)
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

func runManager(t *testing.T, test *managerTest) (done func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		require.NoError(t, test.m.Run(ctx))
	}()
	return func() {
		cancel()
	}
}
