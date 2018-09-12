package node

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/peer"
)

func TestLimit(t *testing.T) {
	l, log := newTestLimiter()

	// Messages under limit are processed "immediately" without logging
	for i := 1; i <= node.AttestLimit; i++ {
		ctx, cancel := context.WithTimeout(newTestContext(), 1*time.Millisecond)
		err := l.Limit(ctx, AttestMsg, 1)
		assert.NoError(t, err)

		if len(log.Entries) > 0 {
			msg, _ := log.LastEntry().String()
			t.Errorf("expected no log lines; got %v", msg)
		}
		cancel()
	}

	// Messages over the limit must wait
	// Bucket exhausted by above loop
	ctx, cancel := context.WithTimeout(newTestContext(), 1*time.Millisecond)
	err := l.Limit(ctx, AttestMsg, 1)
	assert.Error(t, err)

	if len(log.Entries) != 1 {
		t.Errorf("expected 1 log entry; got %v", len(log.Entries))
	}
	cancel()

	// Can't exceed burst size
	count := node.AttestLimit + 1
	err = l.Limit(newTestContext(), AttestMsg, count)
	assert.Error(t, err)
}

func TestLimiterFor(t *testing.T) {
	l, _ := newTestLimiter()

	// New caller for valid message type gets the right limiter
	li, err := l.limiterFor(AttestMsg, "evan")
	require.NoError(t, err)
	require.NotNil(t, li)
	assert.Equal(t, node.AttestLimit, li.Burst())
	assert.Equal(t, l.attestRate, li.Limit())

	// Gets the same limiter when asked for it
	li2, err := l.limiterFor(AttestMsg, "evan")
	require.NoError(t, err)
	assert.Equal(t, li, li2)

	// Invalid message type returns an error
	li, err = l.limiterFor(100, "evan")
	assert.Error(t, err)
}

func TestCallerID(t *testing.T) {
	l, _ := newTestLimiter()
	p := newTestPeer()

	id, err := l.callerID(peer.NewContext(context.Background(), p))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", id)

	// Fails without IP defined
	p.Addr = &net.TCPAddr{
		Port: 100,
	}
	id, err = l.callerID(peer.NewContext(context.Background(), p))
	assert.Error(t, err)

	// Fails when context is not a gRPC peer
	id, err = l.callerID(context.Background())
	assert.Error(t, err)
}

func TestNotify(t *testing.T) {
	l, log := newTestLimiter()

	// First time caller gets logged
	l.notify("evan", AttestMsg)
	assert.Equal(t, 1, len(log.Entries))

	// Should not get notified again, even for different message type
	l.notify("evan", CSRMsg)
	assert.Equal(t, 1, len(log.Entries))
}

func newTestContext() context.Context {
	return peer.NewContext(context.Background(), newTestPeer())
}

func newTestPeer() *peer.Peer {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return &peer.Peer{
		Addr: addr,
	}
}

func newTestLimiter() (*limiter, *test.Hook) {
	log, hook := test.NewNullLogger()
	return NewLimiter(log), hook
}
