package node

import (
	"context"
	"reflect"
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
	expiredFor := defaultJobInterval

	ctx := s.T().Context()

	done := s.setupAndRunManager(ctx, expiredFor)
	defer done()

	// banned node is never pruned
	nodeBanned := &common.AttestedNode{
		SpiffeId:            "spiffe://test.test/banned",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "",
		CanReattest:         true,
		CertNotAfter:        s.clock.Now().Unix(),
	}

	attestedNodeBanned, err := s.ds.CreateAttestedNode(ctx, nodeBanned)
	s.NoError(err)

	// non-reattestable node is pruned when IncludeNonReattestable == true
	nodeNonReattestable := &common.AttestedNode{
		SpiffeId:            "spiffe://test.test/tofu",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CanReattest:         false,
		CertNotAfter:        s.clock.Now().Unix(),
	}
	attestedNodeNonReattestable, err := s.ds.CreateAttestedNode(ctx, nodeNonReattestable)
	s.NoError(err)

	// expired on pruning time
	expired0 := &common.AttestedNode{
		SpiffeId:            "spiffe://test.test/node0",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CanReattest:         true,
		CertNotAfter:        s.clock.Now().Unix(),
	}

	attestedNodeExpired0, err := s.ds.CreateAttestedNode(ctx, expired0)
	s.NoError(err)

	// expires in pruning time + one minute
	expired1 := &common.AttestedNode{
		SpiffeId:            "spiffe://test.test/node1",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CanReattest:         true,
		CertNotAfter:        s.clock.Now().Add(expiredFor + time.Minute).Unix(),
	}

	attestedNodeExpired1, err := s.ds.CreateAttestedNode(ctx, expired1)
	s.NoError(err)

	// no pruning yet
	s.clock.Add(defaultJobInterval)
	s.Require().Eventuallyf(func() bool {
		listResp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
		s.NoError(err)
		return reflect.DeepEqual([]*common.AttestedNode{
			attestedNodeBanned,
			attestedNodeNonReattestable,
			attestedNodeExpired0,
			attestedNodeExpired1,
		}, listResp.Nodes)
	}, 1*time.Second, 100*time.Millisecond, "Failed to prune nodes correctly")

	// prune the first entry
	s.clock.Add(defaultJobInterval)
	s.Require().Eventuallyf(func() bool {
		listResp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
		s.NoError(err)
		return reflect.DeepEqual([]*common.AttestedNode{
			attestedNodeBanned,
			attestedNodeNonReattestable,
			attestedNodeExpired1,
		}, listResp.Nodes)
	}, 1*time.Second, 100*time.Millisecond, "Failed to prune nodes correctly")

	// prune the second entry
	s.clock.Add(defaultJobInterval)
	s.Require().Eventuallyf(func() bool {
		listResp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
		s.NoError(err)
		return reflect.DeepEqual([]*common.AttestedNode{
			attestedNodeBanned,
			attestedNodeNonReattestable,
		}, listResp.Nodes)
	}, 1*time.Second, 100*time.Millisecond, "Failed to prune nodes correctly")

	// explicitly prune non-reattestable node using on-demand API,
	// while overriding the existing pruning cadence
	s.Require().Eventuallyf(func() bool {
		s.m.Prune(ctx, 2*expiredFor, true)
		listResp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
		s.Require().NoError(err)
		return reflect.DeepEqual([]*common.AttestedNode{
			attestedNodeBanned,
		}, listResp.Nodes)
	}, 1*time.Second, 100*time.Millisecond, "Failed to prune nodes correctly")
}

func (s *ManagerSuite) setupAndRunManager(ctx context.Context, expiredFor time.Duration) func() {
	s.m = NewManager(ManagerConfig{
		Clock:     s.clock,
		DataStore: s.ds,
		Log:       s.log,
		Metrics:   s.metrics,
		PruneArgs: PruneArgs{
			ExpiredFor:             expiredFor,
			IncludeNonReattestable: false,
		},
	})

	// override without jitter
	s.m.c.Interval = defaultJobInterval

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
