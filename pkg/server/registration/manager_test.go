package registration

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	ctx := s.T().Context()

	done := s.setupAndRunManager(ctx)
	defer done()

	// expires right on the pruning time
	entry1 := &common.RegistrationEntry{
		EntryId:  "some_ID_1",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test1",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: s.clock.Now().Add(_pruningCadence).Unix(),
	}

	registrationEntry1, err := s.ds.CreateRegistrationEntry(ctx, entry1)

	s.NoError(err)

	// expires in pruning time + one minute
	entry2 := &common.RegistrationEntry{
		EntryId:  "some_ID_2",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test2",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: s.clock.Now().Add(2*_pruningCadence + time.Minute).Unix(),
	}

	registrationEntry2, err := s.ds.CreateRegistrationEntry(ctx, entry2)

	s.NoError(err)

	// expires in pruning time + two minutes
	entry3 := &common.RegistrationEntry{
		EntryId:  "some_ID_3",
		ParentId: "spiffe://test.test/testA",
		SpiffeId: "spiffe://test.test/testA/test3",
		Selectors: []*common.Selector{
			{
				Type:  "type",
				Value: "value",
			},
		},
		EntryExpiry: s.clock.Now().Add(3*_pruningCadence + 2*time.Minute).Unix(),
	}

	registrationEntry3, err := s.ds.CreateRegistrationEntry(ctx, entry3)

	s.NoError(err)

	// no pruning yet
	s.clock.Add(_pruningCadence)
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		listResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
		require.NoError(c, err)
		require.Equal(c, []*common.RegistrationEntry{registrationEntry1, registrationEntry2, registrationEntry3}, listResp.Entries)
	}, 1*time.Second, 100*time.Millisecond, "Expected no entries to have been pruned")

	// prune first entry
	s.clock.Add(_pruningCadence)
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		listResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
		require.NoError(c, err)
		require.Equal(c, []*common.RegistrationEntry{registrationEntry2, registrationEntry3}, listResp.Entries)
	}, 1*time.Second, 100*time.Millisecond, "Expected one entry to have been pruned")

	// prune second entry
	s.clock.Add(_pruningCadence)
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		listResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
		require.NoError(c, err)
		require.Equal(c, []*common.RegistrationEntry{registrationEntry3}, listResp.Entries)
	}, 1*time.Second, 100*time.Millisecond, "Expected two entries to have been pruned")

	// prune third entry
	s.clock.Add(_pruningCadence)
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		listResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
		require.NoError(c, err)
		require.Empty(c, listResp.Entries)
	}, 1*time.Second, 100*time.Millisecond, "Expected all entries to have been pruned")
}

func (s *ManagerSuite) setupAndRunManager(ctx context.Context) func() {
	s.m = NewManager(ManagerConfig{
		Clock:     s.clock,
		DataStore: s.ds,
		Log:       s.log,
		Metrics:   s.metrics,
	})

	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.m.Run(ctx)
	}()
	return func() {
		cancel()
		s.Require().NoError(<-errCh)
	}
}
