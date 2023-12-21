package endpoints

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

func TestPeerTrackerAttestor(t *testing.T) {
	attestor := PeerTrackerAttestor{Attestor: FakeAttestor{}}
	t.Run("requires peertracker watcher on context", func(t *testing.T) {
		selectors, err := attestor.Attest(context.Background())
		spiretest.AssertGRPCStatus(t, err, codes.Internal, "peer tracker watcher missing from context")
		assert.Empty(t, selectors)
	})

	t.Run("fails if peer is not alive", func(t *testing.T) {
		watcher := &FakeWatcher{alive: false}
		selectors, err := attestor.Attest(WithFakeWatcher(watcher))
		spiretest.AssertGRPCStatus(t, err, codes.Unauthenticated, "could not verify existence of the original caller: dead")
		assert.Empty(t, selectors)
		assert.True(t, watcher.closed)
	})

	t.Run("succeeds if peer is alive", func(t *testing.T) {
		watcher := &FakeWatcher{alive: true}
		selectors, err := attestor.Attest(WithFakeWatcher(watcher))
		assert.NoError(t, err)
		assert.Equal(t, []*common.Selector{{Type: "Type", Value: "Value"}}, selectors)
		assert.False(t, watcher.closed)
	})
}

type FakeAttestor struct{}

func (a FakeAttestor) Attest(_ context.Context, pid int) []*common.Selector {
	if pid == os.Getpid() {
		return []*common.Selector{{Type: "Type", Value: "Value"}}
	}
	return nil
}

func WithFakeWatcher(watcher *FakeWatcher) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: peertracker.AuthInfo{
			Watcher: watcher,
		},
	})
}

type FakeWatcher struct {
	alive  bool
	closed bool
}

func (w *FakeWatcher) Close() { w.closed = true }

func (w *FakeWatcher) IsAlive() error {
	if !w.alive {
		return errors.New("dead")
	}
	return nil
}

func (w *FakeWatcher) PID() int32 { return int32(os.Getpid()) }
