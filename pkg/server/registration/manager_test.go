package registration

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
)

func TestManager(t *testing.T) {
	spiretest.Run(t, new(ManagerSuite))
}

type ManagerSuite struct {
	spiretest.Suite

	clock   *clock.Mock
	log     logrus.FieldLogger
	logHook *test.Hook
	ds      *fakedatastore.DataStore
	metrics *fakemetrics.FakeMetrics

	m *Manager
}

func (s *ManagerSuite) SetupTest() {
	s.clock = clock.NewMock(s.T())
	s.log, s.logHook = test.NewNullLogger()
	s.ds = fakedatastore.New(s.T())
	s.metrics = fakemetrics.New()
}

func (s *ManagerSuite) TestPruning() {
	done := s.setupAndRunManager()
	defer done()

	expiry := s.clock.Now().Add(_pruningCandence)

	// expires right on the pruning time
	entry1 := &common.RegistrationEntry{
		EntryId:  "some ID 1",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test1",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: expiry.Unix(),
	}

	createResp1, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry1,
	})

	s.NoError(err)

	// expires in pruning time + one minute
	entry2 := &common.RegistrationEntry{
		EntryId:  "some ID 1",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test2",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: expiry.Add(time.Minute).Unix(),
	}

	createResp2, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry2,
	})

	s.NoError(err)

	// expires in pruning time + two minutes
	entry3 := &common.RegistrationEntry{
		EntryId:  "some ID 1",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test3",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: expiry.Add(2 * time.Minute).Unix(),
	}

	createResp3, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry3,
	})

	s.NoError(err)

	// no pruning yet
	s.NoError(s.m.prune(context.Background()))
	listResp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	s.NoError(err)
	s.Equal([]*common.RegistrationEntry{createResp1.Entry, createResp2.Entry, createResp3.Entry}, listResp.Entries)

	// prune first entry
	s.clock.Add(_pruningCandence + time.Second)
	s.NoError(s.m.prune(context.Background()))
	listResp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	s.NoError(err)
	s.Equal([]*common.RegistrationEntry{createResp2.Entry, createResp3.Entry}, listResp.Entries)

	// prune second entry
	s.clock.Add(time.Minute)
	s.NoError(s.m.prune(context.Background()))
	listResp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	s.NoError(err)
	s.Equal([]*common.RegistrationEntry{createResp3.Entry}, listResp.Entries)

	// prune third entry
	s.clock.Add(time.Minute)
	s.NoError(s.m.prune(context.Background()))
	listResp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	s.NoError(err)
	s.Empty(listResp.Entries)
}

func (s *ManagerSuite) setupAndRunManager() func() {
	s.m = NewManager(ManagerConfig{
		Clock:     s.clock,
		DataStore: s.ds,
		Log:       s.log,
		Metrics:   s.metrics,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.m.Run(ctx)
	}()
	return func() {
		cancel()
		s.Require().NoError(<-errCh)
	}
}
