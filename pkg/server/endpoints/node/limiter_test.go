package node

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"

	"google.golang.org/grpc/peer"
)

func TestLimit(t *testing.T) {
	l, log := newTestLimiter()

	// Messages under limit are processed "immediately" without logging
	for i := 1; i <= attestLimit; i++ {
		ctx, cancel := context.WithTimeout(newTestContext(), 1*time.Millisecond)
		err := l.Limit(ctx, AttestMsg, 1)
		if err != nil {
			t.Errorf("expected operation to complete before deadline; got: %v", err)
		}
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
	if err == nil {
		t.Error("expected operation to fail due to deadline; got: nil")
	}
	if len(log.Entries) != 1 {
		t.Errorf("expected 1 log entry; got %v", len(log.Entries))
	}
	cancel()

	// Can't exceed burst size
	count := attestLimit + 1
	err = l.Limit(newTestContext(), AttestMsg, count)
	if err == nil {
		t.Error("expected error while exceeding burst; got nil")
	}
}

func TestLimiterFor(t *testing.T) {
	l, _ := newTestLimiter()

	// New caller for valid message type gets the right limiter
	li, err := l.limiterFor(AttestMsg, "evan")
	if err != nil {
		t.Errorf("wanted nil; got %v", err)
	}
	if li == nil {
		t.Error("wanted non-nil pointer; got nil")
	}
	if li.Burst() != attestLimit {
		t.Errorf("wanted %v; got %v", attestLimit, li.Burst())
	}
	if li.Limit() != l.attestRate {
		t.Errorf("wanted %v; got %v", l.attestRate, li.Limit())
	}

	// Gets the same limiter when asked for it
	li2, err := l.limiterFor(AttestMsg, "evan")
	if err != nil {
		t.Errorf("wanted no error; got %v", err)
	}
	if li != li2 {
		t.Errorf("wanted %v; got %v", li, li2)
	}

	// Invalid message type returns an error
	li, err = l.limiterFor(100, "evan")
	if err == nil {
		t.Errorf("wanted an error; got nil")
	}
}

func TestCallerID(t *testing.T) {
	l, _ := newTestLimiter()
	p := newTestPeer()

	id, err := l.callerID(peer.NewContext(context.Background(), p))
	if err != nil {
		t.Errorf("wanted nil; got %v", err)
	}
	if id != "127.0.0.1" {
		t.Errorf("wanted 127.0.0.1; got %v", id)
	}

	p.Addr = &net.TCPAddr{
		Port: 100,
	}
	id, err = l.callerID(peer.NewContext(context.Background(), p))
	if err == nil {
		t.Error("wanted error when IP missing; got nil")
	}

	id, err = l.callerID(context.Background())
	if err == nil {
		t.Error("wanted error when context not a peer; got nil")
	}
}

func TestNotify(t *testing.T) {
	l, log := newTestLimiter()

	// First time caller gets logged
	l.notify("evan", AttestMsg)
	if len(log.Entries) != 1 {
		t.Errorf("expected 1 log entry; got %v", len(log.Entries))
	}

	// Should not get notified again, even for different message type
	l.notify("evan", CSRMsg)
	if len(log.Entries) != 1 {
		t.Errorf("expected 0 additional log entries; got %v", len(log.Entries)-1)
	}
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
