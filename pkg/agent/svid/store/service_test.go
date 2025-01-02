package store_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/agent/svid/store"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	td            = spiffeid.RequireTrustDomainFromString("example.org")
	entrySpiffeID = spiffeid.RequireFromPath(td, "/foh")
)

func TestRun(t *testing.T) {
	bundleCerts, err := util.LoadBundleFixture()
	require.NoError(t, err)

	bundle := spiffebundle.New(td)
	bundle.AddX509Authority(bundleCerts[0])

	cert, key, err := util.LoadSVIDFixture()
	require.NoError(t, err)

	now := time.Now()

	for _, tt := range []struct {
		name string
		// records to ready to store
		records []*storecache.Record
		// stores is the list of configured SVIDStores,
		// it contains the list of expected records to be stored
		stores map[string]*fakeSVIDStore
		// logs is the list of expected logs
		logs []spiretest.LogEntry
	}{
		{
			name: "success",
			stores: map[string]*fakeSVIDStore{
				"store1": {
					name:   "store1",
					putReq: make(map[spiffeid.ID]*svidstore.X509SVID),
					expectedPutReq: map[spiffeid.ID]*svidstore.X509SVID{
						entrySpiffeID: {
							SVID: &svidstore.SVID{
								SPIFFEID:   entrySpiffeID,
								Bundle:     []*x509.Certificate{bundleCerts[0]},
								CertChain:  []*x509.Certificate{cert},
								PrivateKey: key,
								ExpiresAt:  now,
							},
							Metadata:         []string{"a:1", "b:2"},
							FederatedBundles: make(map[string][]*x509.Certificate),
						},
					},
				},
			},
			records: []*storecache.Record{
				{
					ID: "foh",
					Entry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
							{Type: "store1", Value: "b:2"},
						},
					},
					Svid: &cache.X509SVID{
						Chain:      []*x509.Certificate{cert},
						PrivateKey: key,
					},
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: bundle,
					},
					ExpiresAt: now,
					Revision:  1,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "SVID stored successfully",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "1",
						telemetry.Entry:          "foh",
						telemetry.SVIDStore:      "store1",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			test := setupTest(t, tt.stores)
			test.cache.records = tt.records

			go func() {
				err := test.service.Run(ctx)
				require.NoError(t, err)
			}()

			// Wait until storeSVID finished
			select {
			case <-test.storeFinishedHook:
			case <-ctx.Done():
				require.Fail(t, "context finished ")
			}

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.logs)

			// Validates expected requests
			for _, s := range tt.stores {
				require.Len(t, s.putReq, len(s.expectedPutReq))

				for key, val := range s.expectedPutReq {
					req := s.putReq[key]
					require.Equal(t, val, req)
				}
			}
		})
	}
}

func TestRunDeleteSecrets(t *testing.T) {
	bundleCerts, err := util.LoadBundleFixture()
	require.NoError(t, err)

	bundle := spiffebundle.New(td)
	bundle.AddX509Authority(bundleCerts[0])

	cert, key, err := util.LoadSVIDFixture()
	require.NoError(t, err)

	now := time.Now()

	for _, tt := range []struct {
		name string
		// readyRecords list of records that are ready to be stored
		readyRecords []*storecache.Record
		// stores is a list of configured SVIDStores,
		// it contains the list of expected configurations to be sent
		stores map[string]*fakeSVIDStore
		// logs is the list of expected logs
		logs []spiretest.LogEntry
	}{
		{
			name: "secret without entry",
			stores: map[string]*fakeSVIDStore{
				"store1": {
					name:              "store1",
					expectedDeleteReq: [][]string{{"a:1", "b:2"}},
				},
			},
			readyRecords: []*storecache.Record{
				{
					ID: "foh",
					HandledEntry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
							{Type: "store1", Value: "b:2"},
						},
					},
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: bundle,
					},
					ExpiresAt: now,
					Revision:  1,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "SVID deleted successfully",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "1",
						telemetry.Entry:          "foh",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
						telemetry.SVIDStore:      "store1",
					},
				},
			},
		},
		{
			name: "delete fails because unexpected selectors",
			stores: map[string]*fakeSVIDStore{
				"store1": {
					name: "store1",
					err:  status.Error(codes.InvalidArgument, "no valid selector"),
				},
			},
			readyRecords: []*storecache.Record{
				{
					ID: "foh",
					HandledEntry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
							{Type: "store1", Value: "i:1"},
						},
					},
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: bundle,
					},
					ExpiresAt: now,
					Revision:  1,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Failed to delete SVID because of malformed selectors",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "1",
						telemetry.Entry:          "foh",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
						telemetry.SVIDStore:      "store1",
						logrus.ErrorKey:          "rpc error: code = InvalidArgument desc = no valid selector",
					},
				},
			},
		},
		{
			name: "failed to delete using store",
			stores: map[string]*fakeSVIDStore{
				"store1": {
					name: "store1",
					err:  status.Error(codes.Internal, "oh! no"),
				},
			},
			readyRecords: []*storecache.Record{
				{
					ID: "foh",
					HandledEntry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
							{Type: "store1", Value: "i:1"},
						},
					},
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: bundle,
					},
					ExpiresAt: now,
					Revision:  1,
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to delete SVID",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "1",
						telemetry.Entry:          "foh",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
						telemetry.SVIDStore:      "store1",
						logrus.ErrorKey:          "rpc error: code = Internal desc = oh! no",
					},
				},
			},
		},
		{
			name: "selectors has changes",
			stores: map[string]*fakeSVIDStore{
				"store1": {
					name:              "store1",
					putReq:            make(map[spiffeid.ID]*svidstore.X509SVID),
					expectedDeleteReq: [][]string{{"a:1", "b:2"}},
					expectedPutReq: map[spiffeid.ID]*svidstore.X509SVID{
						entrySpiffeID: {
							SVID: &svidstore.SVID{
								SPIFFEID:   entrySpiffeID,
								Bundle:     []*x509.Certificate{bundleCerts[0]},
								CertChain:  []*x509.Certificate{cert},
								PrivateKey: key,
								ExpiresAt:  now,
							},
							Metadata:         []string{"a:1"},
							FederatedBundles: make(map[string][]*x509.Certificate),
						},
					},
				},
			},
			readyRecords: []*storecache.Record{
				{
					ID: "foh",
					Entry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						// Selectors is outdated
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
						},
					},
					HandledEntry: &common.RegistrationEntry{
						EntryId:  "foh",
						SpiffeId: "spiffe://example.org/foh",
						Selectors: []*common.Selector{
							{Type: "store1", Value: "a:1"},
							{Type: "store1", Value: "b:2"},
						},
					},
					Bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						td: bundle,
					},
					ExpiresAt: now,
					Revision:  2,
					Svid: &cache.X509SVID{
						Chain:      []*x509.Certificate{cert},
						PrivateKey: key,
					},
				},
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "SVID deleted successfully",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "2",
						telemetry.Entry:          "foh",
						telemetry.SVIDStore:      "store1",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "SVID stored successfully",
					Data: logrus.Fields{
						telemetry.RevisionNumber: "2",
						telemetry.Entry:          "foh",
						telemetry.SVIDStore:      "store1",
						telemetry.SPIFFEID:       "spiffe://example.org/foh",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			test := setupTest(t, tt.stores)
			test.cache.records = tt.readyRecords

			go func() {
				err := test.service.Run(ctx)
				require.NoError(t, err)
			}()

			// Wait until storeSVID finished
			select {
			case <-test.storeFinishedHook:
			case <-ctx.Done():
				require.Fail(t, "context finished")
			}

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.logs)

			// Validates expected requests
			for _, s := range tt.stores {
				require.Len(t, s.putReq, len(s.expectedPutReq))

				for key, val := range s.expectedPutReq {
					req := s.putReq[key]
					require.Equal(t, val, req)
				}

				require.Equal(t, s.expectedDeleteReq, s.deleteReq)
			}
		})
	}
}

type serviceTest struct {
	t       *testing.T
	service *store.SVIDStoreService

	catalog           *fakeCatalog
	clk               *clock.Mock
	logHook           *test.Hook
	cache             *fakeCache
	storeFinishedHook chan struct{}
}

func setupTest(t *testing.T, stores map[string]*fakeSVIDStore) *serviceTest {
	cat := &fakeCatalog{stores: stores}
	clk := clock.NewMock()
	cache := &fakeCache{revisions: make(map[string]int64)}

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	storeFinishedHook := make(chan struct{})

	service := store.New(&store.Config{
		Clk:         clk,
		Log:         log,
		TrustDomain: td,
		Cache:       cache,
		Catalog:     cat,
		Metrics:     telemetry.Blackhole{},
	})
	service.SetStoreFinishedHook(storeFinishedHook)

	return &serviceTest{
		t:                 t,
		service:           service,
		clk:               clk,
		catalog:           cat,
		logHook:           logHook,
		storeFinishedHook: storeFinishedHook,
		cache:             cache,
	}
}

type fakeCatalog struct {
	catalog.Catalog

	stores map[string]*fakeSVIDStore
}

func (c *fakeCatalog) GetSVIDStoreNamed(name string) (svidstore.SVIDStore, bool) {
	svidStore, ok := c.stores[name]
	return svidStore, ok
}

type fakeCache struct {
	records   []*storecache.Record
	revisions map[string]int64
}

func (c *fakeCache) ReadyToStore() []*storecache.Record {
	return c.records
}

func (c *fakeCache) HandledRecord(entry *common.RegistrationEntry, revision int64) {
	c.revisions[entry.EntryId] = revision
}

type fakeSVIDStore struct {
	svidstore.SVIDStore

	name              string
	err               error
	putReq            map[spiffeid.ID]*svidstore.X509SVID
	expectedPutReq    map[spiffeid.ID]*svidstore.X509SVID
	deleteReq         [][]string
	expectedDeleteReq [][]string
}

func (s *fakeSVIDStore) Name() string {
	return s.name
}

func (s *fakeSVIDStore) PutX509SVID(_ context.Context, req *svidstore.X509SVID) error {
	if s.err != nil {
		return s.err
	}
	s.putReq[req.SVID.SPIFFEID] = req

	return nil
}

func (s *fakeSVIDStore) DeleteX509SVID(_ context.Context, req []string) error {
	if s.err != nil {
		return s.err
	}

	s.deleteReq = append(s.deleteReq, req)
	return nil
}
