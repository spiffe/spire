package workload

import (
	"testing"
	"time"
)

func TestBackoff_Next(t *testing.T) {
	bo := newBackoff(10 * time.Second)

	// Initial delay should be equal to the start duration
	if bo.next() != backoffStartDuration {
		t.Errorf("got: %v; want: %v", bo.delay(), backoffStartDuration)
	}

	// next() should have incremented the delay
	expectedDelay := backoffStartDuration + backoffStartDuration
	if bo.delay() != expectedDelay {
		t.Errorf("got: %v; want: %v", bo.delay(), expectedDelay)
	}
}

func TestBackoff_Expired(t *testing.T) {
	timeout := 2 * time.Second
	bo := newBackoff(timeout)

	if bo.expired() {
		t.Errorf("backoff expired immediately; timeout: %v; current delay: %v", timeout, bo.delay())
	}

	bo.next()
	if !bo.expired() {
		t.Errorf("backoff should have expired; timeout: %v; current delay: %v", timeout, bo.delay())
	}
}

func TestBackoff_Reset(t *testing.T) {
	bo := newBackoff(10 * time.Second)

	bo.next()
	bo.reset()
	if bo.delay() != backoffStartDuration {
		t.Errorf("backoff did not reset; got: %v, want: %v", bo.delay(), backoffStartDuration)
	}
}

func TestBackoff_Ticker(t *testing.T) {
	bo := newBackoff(10 * time.Second)

	bo.current = 1 * time.Millisecond
	select {
	case <-time.NewTicker(5 * time.Millisecond).C:
		t.Errorf("ticker did not fire in time")
	case <-bo.ticker():
		break
	}
}
